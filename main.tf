# ---------------------------------------------------------------------
# Basic AWS data sources to gather region and caller info
# ---------------------------------------------------------------------
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------
# 1. Secure SSM parameter storing the list of blocked IPs as JSON
# ---------------------------------------------------------------------
resource "aws_ssm_parameter" "ip_block_list" {
  #checkov:skip=CKV_AWS_337:"Skipping KMS check as AWS-managed key is acceptable"
  name   = var.ssm_parameter_name
  type   = "SecureString"
  value  = "[]" # Initialized empty list of blocked IPs
  lifecycle {
    ignore_changes = [value] # Allows SOC to edit manually outside Terraform
  }
}

# ---------------------------------------------------------------------
# 2. WAF IP Set populated from the SSM parameter
# ---------------------------------------------------------------------
resource "aws_wafv2_ip_set" "mp_waf_ip_set" {
  name               = "${local.base_name}-ip-set"
  scope              = "REGIONAL"
  ip_address_version = var.ip_address_version
  description        = "Addresses blocked by ${local.base_name} populated from SSM"
  addresses          = jsondecode(aws_ssm_parameter.ip_block_list.value)
  tags               = local.tags
}

# ---------------------------------------------------------------------
# 3. CloudWatch log group for WAF logging (only if custom destination not given)
# ---------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "mp_waf_cloudwatch_log_group" {
  count             = var.log_destination_arn == null ? 1 : 0
  name              = "aws-waf-logs-${local.base_name}"
  retention_in_days = var.log_retention_in_days
  tags              = local.tags
}

# ---------------------------------------------------------------------
# 4. WAF Web ACL with multiple optional and dynamic rules
# ---------------------------------------------------------------------
resource "aws_wafv2_web_acl" "mp_waf_acl" {
  name        = local.base_name
  scope       = "REGIONAL"
  description = "AWS WAF protecting ${local.base_name}"
  depends_on  = [aws_wafv2_ip_set.mp_waf_ip_set]

  default_action {
    allow {} # Default action is to allow traffic
  }

  # Rule 1: Explicit block list using IP set
  rule {
    name     = "${local.base_name}-blocked-ip"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.mp_waf_ip_set.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.base_name}-blocked-ip"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: Optional DDoS rate-based blocking
  dynamic "rule" {
    for_each = var.enable_ddos_protection ? [1] : []
    content {
      name     = "shield-block"
      priority = 2

      action {
        block {}
      }

      statement {
        rate_based_statement {
          limit              = var.ddos_rate_limit
          aggregate_key_type = "IP"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "shield-block"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 3: Optional geo-block (allow only UK)
  dynamic "rule" {
    for_each = var.block_non_uk_traffic ? [1] : []
    content {
      name     = "block-non-uk"
      priority = 3

      action {
        block {}
      }

      statement {
        not_statement {
          statement {
            geo_match_statement {
              country_codes = ["GB"]
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "block-non-uk"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rule 4+: Managed AWS rule groups with custom priority and override action
  dynamic "rule" {
    for_each = local.managed_rule_groups_with_priority
    content {
      name     = rule.value.name
      priority = rule.value.priority

      override_action {
        dynamic "count" {
          for_each = rule.value.override_action == "count" ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = rule.value.override_action == "none" ? [1] : []
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = rule.value.vendor_name
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }

  # Optional: Additional managed rules (fallback priority starts at 1000)
  dynamic "rule" {
    for_each = var.additional_managed_rules
    content {
      name     = rule.value.name
      priority = 1000 + index(var.additional_managed_rules, rule.value)

      override_action {
        dynamic "count" {
          for_each = rule.value.override_action == "count" ? [1] : []
          content {}
        }
        dynamic "none" {
          for_each = rule.value.override_action == "none" || rule.value.override_action == null ? [1] : []
          content {}
        }
      }

      statement {
        managed_rule_group_statement {
          name        = rule.value.name
          vendor_name = rule.value.vendor_name
          version     = try(rule.value.version, null)
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value.name
        sampled_requests_enabled   = true
      }
    }
  }

  # Web ACL-level visibility settings
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = local.base_name
    sampled_requests_enabled   = true
  }

  tags = local.tags
}

# ---------------------------------------------------------------------
# 5. CloudWatch log permissions and integration with WAF
# ---------------------------------------------------------------------
data "aws_iam_policy_document" "waf" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [
      "${coalesce(var.log_destination_arn, aws_cloudwatch_log_group.mp_waf_cloudwatch_log_group[0].arn)}:*"
    ]
  }
}

resource "aws_cloudwatch_log_resource_policy" "mp_waf_log_policy" {
  policy_name     = "${local.base_name}-resource-policy"
  policy_document = data.aws_iam_policy_document.waf.json
}

resource "aws_wafv2_web_acl_logging_configuration" "mp_waf_log_config" {
  resource_arn = aws_wafv2_web_acl.mp_waf_acl.arn
  log_destination_configs = [
    coalesce(var.log_destination_arn, aws_cloudwatch_log_group.mp_waf_cloudwatch_log_group[0].arn)
  ]
  depends_on = [aws_cloudwatch_log_resource_policy.mp_waf_log_policy]
}

# ---------------------------------------------------------------------
# 6. Associate the WAF Web ACL with external resources (ALB, CloudFront, etc.)
# ---------------------------------------------------------------------
resource "aws_wafv2_web_acl_association" "mp_waf_acl_association" {
  for_each     = toset(var.associated_resource_arns)
  resource_arn = each.value
  web_acl_arn  = aws_wafv2_web_acl.mp_waf_acl.arn
}

# ---------------------------------------------------------------------
# IAM role and policy to forward logs to core logging account
# ---------------------------------------------------------------------
resource "aws_iam_role" "cwl_to_core_logging" {
  name = "${local.base_name}-cwl-to-core-logging"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "logs.${data.aws_region.current.name}.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cwl_to_core_logging_policy" {
  name = "${local.base_name}-cwl-to-core-logging-policy"
  role = aws_iam_role.cwl_to_core_logging.name

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["logs:PutSubscriptionFilter"],
      Resource = local.core_logging_cw_destination_resource
    }]
  })
}

# Optional: Forward logs to core logging account if enabled
resource "aws_cloudwatch_log_subscription_filter" "forward_to_core_logging" {
  count = var.enable_core_logging ? 1 : 0

  name            = "${local.base_name}-waf-to-core-logging"
  log_group_name  = aws_cloudwatch_log_group.mp_waf_cloudwatch_log_group[0].name
  filter_pattern  = "{$.action = * }"
  destination_arn = local.core_logging_cw_destination_arn
  role_arn        = aws_iam_role.cwl_to_core_logging.arn

  depends_on = [
    aws_cloudwatch_log_group.mp_waf_cloudwatch_log_group,
    aws_iam_role_policy.cwl_to_core_logging_policy
  ]
}

# ---------------------------------------------------------------------
# Optional DDoS alarms via SNS topic and CloudWatch alarms
# ---------------------------------------------------------------------
data "aws_kms_key" "sns" {
  count  = var.enable_ddos_alarms ? 1 : 0
  key_id = "alias/aws/sns"
}

resource "aws_sns_topic" "ddos_alarm" {
  count             = var.enable_ddos_alarms ? 1 : 0
  name              = "${var.application_name}_ddos_alarm"
  kms_master_key_id = data.aws_kms_key.sns[0].id
}

resource "aws_cloudwatch_metric_alarm" "ddos" {
  for_each = var.enable_ddos_alarms ? var.ddos_alarm_resources : {}

  alarm_name          = format("DDoSDetected-%s", each.key)
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "DDoSDetected"
  namespace           = "AWS/DDoSProtection"
  period              = 60
  statistic           = "Average"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_description   = "Triggers when AWS Shield Advanced detects a DDoS attack"
  alarm_actions       = [aws_sns_topic.module_ddos_alarm[0].arn]
  ok_actions          = [aws_sns_topic.module_ddos_alarm[0].arn]
  dimensions = {
    ResourceArn = each.value["arn"]
  }
}

# ---------------------------------------------------------------------
# PagerDuty integration for DDoS alarm forwarding
# ---------------------------------------------------------------------
data "aws_secretsmanager_secret" "pagerduty_integration_keys" {
  count    = var.enable_pagerduty_integration ? 1 : 0
  provider = aws.modernisation-platform
  name     = "pagerduty_integration_keys"
}

data "aws_secretsmanager_secret_version" "pagerduty_integration_keys" {
  count     = var.enable_pagerduty_integration ? 1 : 0
  provider  = aws.modernisation-platform
  secret_id = data.aws_secretsmanager_secret.pagerduty_integration_keys[0].id
}

module "pagerduty_core_alerts" {
  count                     = var.enable_pagerduty_integration ? 1 : 0
  depends_on                = [aws_sns_topic.ddos_alarm]
  source                    = "github.com/ministryofjustice/modernisation-platform-terraform-pagerduty-integration?ref=d88bd90d490268896670a898edfaba24bba2f8ab" # v3.0.0
  sns_topics                = [aws_sns_topic.ddos_alarm[0].name]
  pagerduty_integration_key = local.pagerduty_integration_keys["ddos_cloudwatch"]
}

resource "aws_sns_topic" "module_ddos_alarm" {
  count             = var.enable_ddos_alarms ? 1 : 0
  name              = format("%s_ddos_alarm", var.application_name)
  kms_master_key_id = data.aws_kms_key.sns[0].id
}
