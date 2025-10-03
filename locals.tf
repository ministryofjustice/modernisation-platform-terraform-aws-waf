locals {
  base_name                            = lower(format("%s-waf", var.application_name))
  tags                                 = merge(var.tags, { Name = local.base_name })
  core_logging_account_id              = var.core_logging_account_id
  core_logging_cw_destination_arn      = "arn:aws:logs:eu-west-2:${local.core_logging_account_id}:destination:waf-logs-destination"
  core_logging_cw_destination_resource = "arn:aws:logs:eu-west-2:${local.core_logging_account_id}:destination/waf-logs-destination"
  pagerduty_integration_keys           = var.enable_pagerduty_integration ? jsondecode(data.aws_secretsmanager_secret_version.pagerduty_integration_keys[0].secret_string) : {}
  ddos_enabled                         = var.enable_ddos_protection
  ddos_rate_limit_valid                = !local.ddos_enabled || (local.ddos_enabled && var.ddos_rate_limit > 0)
}


resource "null_resource" "validate_ddos_config" {
  count = var.enable_ddos_protection && var.ddos_rate_limit == null ? 1 : 0

  provisioner "local-exec" {
    command = "echo 'ERROR: ddos_rate_limit must be set when enable_ddos_protection is true' && exit 1"
  }
}

#############################################
# Managed rule groups: default order + prio
#############################################

# Keep this list aligned with the AWS managed groups the module supports.
# (It mirrors the order that was previously hardcoded.)
locals {
  default_managed_rule_order = [
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesSQLiRuleSet",
    "AWSManagedRulesLinuxRuleSet",
    "AWSManagedRulesAnonymousIpList",
    "AWSManagedRulesBotControlRuleSet",
  ]

  # Provide spaced defaults (10,20,30,...) so users can insert in-between later.
  default_managed_rule_priority_map = {
    for idx, name in local.default_managed_rule_order :
    name => (idx + 1) * 10
  }

  # Final priority map: user overrides win, defaults fill the rest
  effective_managed_rule_priority_map = merge(
    local.default_managed_rule_priority_map,
    var.managed_rule_priorities
  )

  # Build the structure expected by main.tf's dynamic "rule"
  # managed_rule_actions is expected to be a map(name => bool):
  #   true  => override_action = "count"
  #   false => override_action = "none" (respect vendor actions; typically block)
  managed_rule_groups_with_priority = [
    for name in local.default_managed_rule_order : {
      name            = name
      vendor_name     = "AWS"
      override_action = (try(var.managed_rule_actions[name], false) ? "count" : "none")
      priority        = local.effective_managed_rule_priority_map[name]
    }
    if contains(keys(var.managed_rule_actions), name)
  ]

  #########################################
  # Sanity checks to prevent collisions
  #########################################

  # Static priorities already consumed by fixed rules in main.tf
  # Rule 1: blocked-ip  (priority = 1)
  # Rule 2: shield      (priority = 2) only if enabled
  # Rule 3: block-non-uk(priority = 3) only if enabled
  static_priorities_in_use = concat(
    [1],
    var.enable_ddos_protection ? [2] : [],
    var.block_non_uk_traffic ? [3] : []
  )

  managed_priorities = [for r in local.managed_rule_groups_with_priority : r.priority]

  all_priorities_in_use = concat(local.static_priorities_in_use, local.managed_priorities)

  priorities_are_unique = length(distinct(local.all_priorities_in_use)) == length(local.all_priorities_in_use)
}
