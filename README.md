# Modernisation Platform Terraform AWS WAF Module

[![Standards Icon]][Standards Link] [![Format Code Icon]][Format Code Link] [![Scorecards Icon]][Scorecards Link] [![SCA Icon]][SCA Link] [![Terraform SCA Icon]][Terraform SCA Link]

## 🚧 Known Issues & Limitations

1. This module was created from a previous module here - <https://github.com/ministryofjustice/modernisation-platform-terraform-waf>

## Why use this module?

- Batteries‑included WAF: opinionated defaults for common web risks (SQLi, bad inputs, bot control, anonymous IPs, etc.).

- Configurable: enable/disable each AWS Managed Rule Group and add your own via additional_managed_rules.

- Simple IP blocking: maintain a plain list of IPs in SSM Parameter Store — the module turns it into an IP set.

- Logs wired for you: CloudWatch log group + subscription filter to the core‑logging account.

- Operational signals: optional DDoS threshold alarm and optional PagerDuty integration.

- Works with multiple resources: associate the Web ACL with one or many LBs/CloudFront distributions via ARNs.

⚠️ Rule ordering/priorities – now supported. Earlier limitations noted in the repo history have been addressed.

---

## Requirements

- Terraform: ~> 1.0

- Provider: hashicorp/aws ~> 6.0

The module also expects access to the Modernisation Platform logging account ID when log shipping is enabled.

## Usage

This module offers various WAF rules as a module, custom ones such as IP Address blocking from an SSM parameter, as well as AWS-managed ones.

With the `managed_rule_actions` if the bool is true, it will block traffic, false will leave it in a count mode.

You can pass in more AWS rules with `additional_managed_rules` like the example below.

For `associated_resource_arns` you can supply one or multiple ones.

For `enable_ddos_protection` it covers what is currently offered in the FM module.

```hcl

module "waf" {
  source                   = "git::https://github.com/ministryofjustice/modernisation-platform-terraform-aws-waf"
  enable_pagerduty_integration = true
  enable_ddos_protection = true
  ddos_rate_limit        = 5000
  block_non_uk_traffic   = false
  associated_resource_arns = [aws_lb.waf_lb.arn]
  managed_rule_actions = {
    AWSManagedRulesKnownBadInputsRuleSet = false
    AWSManagedRulesCommonRuleSet         = false
    AWSManagedRulesSQLiRuleSet           = false
    AWSManagedRulesLinuxRuleSet          = false
    AWSManagedRulesAnonymousIpList       = false
    AWSManagedRulesBotControlRuleSet     = false
  }

  core_logging_account_id = local.environment_management.account_ids["core-logging-production"]

  application_name = local.application_name
  tags             = local.tags

  additional_managed_rules = [
  {
    name            = "AWSManagedRulesPHPRuleSet"
    vendor_name     = "AWS"
    override_action = "count"
  },
  {
    name        = "AWSManagedRulesUnixRuleSet"
    vendor_name = "AWS"
    override_action = "count"
  }
]
}


```

## How it works (under the hood)

- aws_wafv2_web_acl with rule groups for the selected AWS Managed Rule Sets and any extras you pass via additional_managed_rules.

- IP set created from an SSM Parameter (if supplied) and referenced by a WAF rule to block listed IPs.

- Logging: CloudWatch log group + resource policy and a subscription filter to the core‑logging account.

- DDoS alarm: rate‑based metric alarm and optional SNS topic → PagerDuty integration.

## Associating with resources

Provide one or more ARNs via associated_resource_arns. Common examples:

`ALB: aws_lb.<name>.arn`

`CloudFront: distribution ARN (ensure the Web ACL scope matches your target; regional ALB vs. CloudFront global)`

If you’re using CloudFront, ensure you create the Web ACL in the CLOUDFRONT scope; for regional resources (ALB, API Gateway), use REGIONAL. This module handles association via the ARNs you provide.

## Security

No secrets should be committed to this repository.

WAF logs contain security‑sensitive data; ensure access to the log group and the cross‑account subscription is restricted.

<!--- BEGIN_TF_DOCS --->

<!--- END_TF_DOCS --->

## Looking for issues?

If you're looking to raise an issue with this module, please create a new issue in the [Modernisation Platform repository](https://github.com/ministryofjustice/modernisation-platform/issues).

<!-- BEGIN_TF_DOCS -->

## Requirements

| Name                                                                     | Version |
| ------------------------------------------------------------------------ | ------- |
| <a name="requirement_terraform"></a> [terraform](#requirement_terraform) | ~> 1.0  |
| <a name="requirement_aws"></a> [aws](#requirement_aws)                   | ~> 6.0  |

## Providers

| Name                                                                                                                  | Version |
| --------------------------------------------------------------------------------------------------------------------- | ------- |
| <a name="provider_aws"></a> [aws](#provider_aws)                                                                      | ~> 6.0  |
| <a name="provider_aws.modernisation-platform"></a> [aws.modernisation-platform](#provider_aws.modernisation-platform) | ~> 6.0  |
| <a name="provider_null"></a> [null](#provider_null)                                                                   | n/a     |

## Modules

| Name                                                                                               | Source                                                                              | Version                                  |
| -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------- |
| <a name="module_pagerduty_core_alerts"></a> [pagerduty_core_alerts](#module_pagerduty_core_alerts) | github.com/ministryofjustice/modernisation-platform-terraform-pagerduty-integration | d88bd90d490268896670a898edfaba24bba2f8ab |

## Resources

| Name                                                                                                                                                                             | Type        |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| [aws_cloudwatch_log_group.mp_waf_cloudwatch_log_group](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group)                         | resource    |
| [aws_cloudwatch_log_resource_policy.mp_waf_log_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_resource_policy)               | resource    |
| [aws_cloudwatch_log_subscription_filter.forward_to_core_logging](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_subscription_filter) | resource    |
| [aws_cloudwatch_metric_alarm.ddos](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm)                                          | resource    |
| [aws_iam_role.cwl_to_core_logging](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role)                                                         | resource    |
| [aws_iam_role_policy.cwl_to_core_logging_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy)                                    | resource    |
| [aws_sns_topic.ddos_alarm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic)                                                                | resource    |
| [aws_sns_topic.module_ddos_alarm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic)                                                         | resource    |
| [aws_ssm_parameter.ip_block_list](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter)                                                     | resource    |
| [aws_wafv2_ip_set.mp_waf_ip_set](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set)                                                       | resource    |
| [aws_wafv2_web_acl.mp_waf_acl](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl)                                                        | resource    |
| [aws_wafv2_web_acl_association.mp_waf_acl_association](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_association)                    | resource    |
| [aws_wafv2_web_acl_logging_configuration.mp_waf_log_config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_logging_configuration)     | resource    |
| [null_resource.validate_ddos_config](https://registry.terraform.io/providers/hashicorp/null/latest/docs/resources/resource)                                                      | resource    |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity)                                                    | data source |
| [aws_iam_policy_document.waf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document)                                                | data source |
| [aws_kms_key.sns](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/kms_key)                                                                        | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region)                                                                      | data source |
| [aws_secretsmanager_secret.pagerduty_integration_keys](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/secretsmanager_secret)                     | data source |
| [aws_secretsmanager_secret_version.pagerduty_integration_keys](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/secretsmanager_secret_version)     | data source |

## Inputs

| Name                                                                                                                  | Description                                                                                                                                                                                                                                                                                                                                                                                                             | Type                                                                                                                                                                                                                                             | Default                                                                                                                                                                                                                                                                                                                                                                                        | Required |
| --------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------: | --- |
| <a name="input_additional_managed_rules"></a> [additional_managed_rules](#input_additional_managed_rules)             | Additional rule attachments to include in the WebACL.<br/>Supply either:<br/>- Managed: { name, vendor_name, version?, override_action?, priority? }<br/>- External by ARN: { arn, override_action?, priority? }<br/><br/>If 'priority' is omitted, a fallback of 1000 + index(...) is used.                                                                                                                            | <pre>list(object({<br/> # Managed path:<br/> name = optional(string)<br/> vendor_name = optional(string)<br/> version = optional(string)<br/> # External path:<br/> arn = optional(string)<br/><br/> override_action = optional(string) # "none" | "count"<br/> priority = optional(number)<br/> }))</pre>                                                                                                                                                                                                                                                                                                                                        |   `[]`   | no  |
| <a name="input_application_name"></a> [application_name](#input_application_name)                                     | Application identifier used for naming and tagging.                                                                                                                                                                                                                                                                                                                                                                     | `string`                                                                                                                                                                                                                                         | n/a                                                                                                                                                                                                                                                                                                                                                                                            |   yes    |
| <a name="input_associated_resource_arns"></a> [associated_resource_arns](#input_associated_resource_arns)             | List of resource ARNs (e.g. ALB, CloudFront distribution) to associate with the Web ACL.                                                                                                                                                                                                                                                                                                                                | `list(string)`                                                                                                                                                                                                                                   | `[]`                                                                                                                                                                                                                                                                                                                                                                                           |    no    |
| <a name="input_block_non_uk_traffic"></a> [block_non_uk_traffic](#input_block_non_uk_traffic)                         | If true, add a WAF rule that blocks any request not originating from the United Kingdom (GB).                                                                                                                                                                                                                                                                                                                           | `bool`                                                                                                                                                                                                                                           | `false`                                                                                                                                                                                                                                                                                                                                                                                        |    no    |
| <a name="input_blocked_ip_rule_priority"></a> [blocked_ip_rule_priority](#input_blocked_ip_rule_priority)             | Priority for the IP-set 'blocked-ip' rule.                                                                                                                                                                                                                                                                                                                                                                              | `number`                                                                                                                                                                                                                                         | `1`                                                                                                                                                                                                                                                                                                                                                                                            |    no    |
| <a name="input_core_logging_account_id"></a> [core_logging_account_id](#input_core_logging_account_id)                | Account ID for core logging.                                                                                                                                                                                                                                                                                                                                                                                            | `string`                                                                                                                                                                                                                                         | `""`                                                                                                                                                                                                                                                                                                                                                                                           |    no    |
| <a name="input_ddos_alarm_resources"></a> [ddos_alarm_resources](#input_ddos_alarm_resources)                         | Map of resources to monitor for DDoS alarms. Each value must contain 'arn'.                                                                                                                                                                                                                                                                                                                                             | <pre>map(object({<br/> arn = string<br/> }))</pre>                                                                                                                                                                                               | `{}`                                                                                                                                                                                                                                                                                                                                                                                           |    no    |
| <a name="input_ddos_rate_limit"></a> [ddos_rate_limit](#input_ddos_rate_limit)                                        | Requests per 5-minute window that triggers the DDoS rate-based block. Required when enable_ddos_protection = true.                                                                                                                                                                                                                                                                                                      | `number`                                                                                                                                                                                                                                         | n/a                                                                                                                                                                                                                                                                                                                                                                                            |   yes    |
| <a name="input_enable_core_logging"></a> [enable_core_logging](#input_enable_core_logging)                            | Whether to enable forwarding logs to the core logging account.                                                                                                                                                                                                                                                                                                                                                          | `bool`                                                                                                                                                                                                                                           | `true`                                                                                                                                                                                                                                                                                                                                                                                         |    no    |
| <a name="input_enable_ddos_alarms"></a> [enable_ddos_alarms](#input_enable_ddos_alarms)                               | Enable DDoS protection CloudWatch alarms.                                                                                                                                                                                                                                                                                                                                                                               | `bool`                                                                                                                                                                                                                                           | `true`                                                                                                                                                                                                                                                                                                                                                                                         |    no    |
| <a name="input_enable_ddos_protection"></a> [enable_ddos_protection](#input_enable_ddos_protection)                   | If true (default), create a Shield-style rate-based blocking rule at the WebACL.                                                                                                                                                                                                                                                                                                                                        | `bool`                                                                                                                                                                                                                                           | `true`                                                                                                                                                                                                                                                                                                                                                                                         |    no    |
| <a name="input_enable_pagerduty_integration"></a> [enable_pagerduty_integration](#input_enable_pagerduty_integration) | Enable PagerDuty SNS integration for DDoS alarms.                                                                                                                                                                                                                                                                                                                                                                       | `bool`                                                                                                                                                                                                                                           | `true`                                                                                                                                                                                                                                                                                                                                                                                         |    no    |
| <a name="input_ip_address_version"></a> [ip_address_version](#input_ip_address_version)                               | IP version for the IP set (IPV4 or IPV6).                                                                                                                                                                                                                                                                                                                                                                               | `string`                                                                                                                                                                                                                                         | `"IPV4"`                                                                                                                                                                                                                                                                                                                                                                                       |    no    |
| <a name="input_log_destination_arn"></a> [log_destination_arn](#input_log_destination_arn)                            | Optional ARN of an existing CloudWatch Log Group to send WAF logs to.                                                                                                                                                                                                                                                                                                                                                   | `string`                                                                                                                                                                                                                                         | `null`                                                                                                                                                                                                                                                                                                                                                                                         |    no    |
| <a name="input_log_retention_in_days"></a> [log_retention_in_days](#input_log_retention_in_days)                      | Retention period for the WAF logs.                                                                                                                                                                                                                                                                                                                                                                                      | `number`                                                                                                                                                                                                                                         | `365`                                                                                                                                                                                                                                                                                                                                                                                          |    no    |
| <a name="input_managed_rule_actions"></a> [managed_rule_actions](#input_managed_rule_actions)                         | Map of AWS Managed Rule Group names to boolean flag indicating whether to block (true) or count (false).                                                                                                                                                                                                                                                                                                                | `map(bool)`                                                                                                                                                                                                                                      | `{}`                                                                                                                                                                                                                                                                                                                                                                                           |    no    |
| <a name="input_managed_rule_enforce"></a> [managed_rule_enforce](#input_managed_rule_enforce)                         | When true, AWS Managed Rule Groups are set to block (override_action = "none"). When false (default) they run in count mode.                                                                                                                                                                                                                                                                                            | `bool`                                                                                                                                                                                                                                           | `false`                                                                                                                                                                                                                                                                                                                                                                                        |    no    |
| <a name="input_managed_rule_groups"></a> [managed_rule_groups](#input_managed_rule_groups)                            | List of managed rule groups to enable. Each object supports:<br/> _ name – (Required) Rule group name, e.g. "AWSManagedRulesCommonRuleSet".<br/> _ vendor_name – (Optional) Defaults to "AWS".<br/> _ override_action – (Optional) "count" or "none". If omitted, the module uses managed_rule_enforce to decide.<br/> _ priority – (Optional) Rule priority. If omitted, the module assigns priorities starting at 10. | <pre>list(object({<br/> name = string<br/> vendor_name = optional(string, "AWS")<br/> override_action = optional(string)<br/> priority = optional(number)<br/> }))</pre>                                                                         | <pre>[<br/> {<br/> "name": "AWSManagedRulesKnownBadInputsRuleSet"<br/> },<br/> {<br/> "name": "AWSManagedRulesCommonRuleSet"<br/> },<br/> {<br/> "name": "AWSManagedRulesSQLiRuleSet"<br/> },<br/> {<br/> "name": "AWSManagedRulesLinuxRuleSet"<br/> },<br/> {<br/> "name": "AWSManagedRulesAnonymousIpList"<br/> },<br/> {<br/> "name": "AWSManagedRulesBotControlRuleSet"<br/> }<br/>]</pre> |    no    |
| <a name="input_managed_rule_priorities"></a> [managed_rule_priorities](#input_managed_rule_priorities)                | Map of AWS Managed Rule Group names to explicit priority integers.<br/>Lower numbers are evaluated first (higher priority).<br/>If omitted for a rule, a sensible default order is used (10,20,30…).                                                                                                                                                                                                                    | `map(number)`                                                                                                                                                                                                                                    | `{}`                                                                                                                                                                                                                                                                                                                                                                                           |    no    |
| <a name="input_ssm_parameter_name"></a> [ssm_parameter_name](#input_ssm_parameter_name)                               | Name of the SSM SecureString parameter that stores the JSON-encoded blocked IP list.                                                                                                                                                                                                                                                                                                                                    | `string`                                                                                                                                                                                                                                         | `"/waf/ip_block_list"`                                                                                                                                                                                                                                                                                                                                                                         |    no    |
| <a name="input_tags"></a> [tags](#input_tags)                                                                         | Common tags applied to all resources.                                                                                                                                                                                                                                                                                                                                                                                   | `map(string)`                                                                                                                                                                                                                                    | `{}`                                                                                                                                                                                                                                                                                                                                                                                           |    no    |
| <a name="input_web_acl_name"></a> [web_acl_name](#input_web_acl_name)                                                 | Explicit name for the WAFv2 Web ACL. If null, defaults to app name (lowercased).                                                                                                                                                                                                                                                                                                                                        | `string`                                                                                                                                                                                                                                         | `null`                                                                                                                                                                                                                                                                                                                                                                                         |    no    |

## Outputs

| Name                                                                                                           | Description                                                                                      |
| -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| <a name="output_ddos_alarm_sns_topic_name"></a> [ddos_alarm_sns_topic_name](#output_ddos_alarm_sns_topic_name) | Name of the DDoS alarms SNS topic used by the PagerDuty integration module.                      |
| <a name="output_ddos_alarm_topic_arn"></a> [ddos_alarm_topic_arn](#output_ddos_alarm_topic_arn)                | ARN of the SNS topic used for DDoS alarms.                                                       |
| <a name="output_effective_web_acl_name"></a> [effective_web_acl_name](#output_effective_web_acl_name)          | The effective Web ACL name used by the module.                                                   |
| <a name="output_ip_set_arn"></a> [ip_set_arn](#output_ip_set_arn)                                              | ARN of the IP set used for blocking.                                                             |
| <a name="output_log_group_name"></a> [log_group_name](#output_log_group_name)                                  | Name of the CloudWatch log group containing WAF logs (null if log_destination_arn was provided). |
| <a name="output_waf_log_group_arn"></a> [waf_log_group_arn](#output_waf_log_group_arn)                         | ARN of the log group receiving WAF logs.                                                         |
| <a name="output_web_acl_arn"></a> [web_acl_arn](#output_web_acl_arn)                                           | ARN of the WAFv2 Web ACL.                                                                        |
| <a name="output_web_acl_name"></a> [web_acl_name](#output_web_acl_name)                                        | Name of the WAF Web ACL.                                                                         |

<!-- END_TF_DOCS -->

[Standards Link]: https://github-community.service.justice.gov.uk/repository-standards/modernisation-platform-terraform-module-template "Repo standards badge."
[Standards Icon]: https://github-community.service.justice.gov.uk/repository-standards/api/modernisation-platform-terraform-module-template/badge
[Format Code Icon]: https://img.shields.io/github/actions/workflow/status/ministryofjustice/modernisation-platform-terraform-module-template/format-code.yml?labelColor=231f20&style=for-the-badge&label=Formate%20Code
[Format Code Link]: https://github.com/ministryofjustice/modernisation-platform-terraform-module-template/actions/workflows/format-code.yml
[Scorecards Icon]: https://img.shields.io/github/actions/workflow/status/ministryofjustice/modernisation-platform-terraform-module-template/scorecards.yml?branch=main&labelColor=231f20&style=for-the-badge&label=Scorecards
[Scorecards Link]: https://github.com/ministryofjustice/modernisation-platform-terraform-module-template/actions/workflows/scorecards.yml
[SCA Icon]: https://img.shields.io/github/actions/workflow/status/ministryofjustice/modernisation-platform-terraform-module-template/code-scanning.yml?branch=main&labelColor=231f20&style=for-the-badge&label=Secure%20Code%20Analysis
[SCA Link]: https://github.com/ministryofjustice/modernisation-platform-terraform-module-template/actions/workflows/code-scanning.yml
[Terraform SCA Icon]: https://img.shields.io/github/actions/workflow/status/ministryofjustice/modernisation-platform-terraform-module-template/code-scanning.yml?branch=main&labelColor=231f20&style=for-the-badge&label=Terraform%20Static%20Code%20Analysis
[Terraform SCA Link]: https://github.com/ministryofjustice/modernisation-platform-terraform-module-template/actions/workflows/terraform-static-analysis.yml
