# Modernisation Platform Terraform Module Template 

[![Standards Icon]][Standards Link] [![Format Code Icon]][Format Code Link] [![Scorecards Icon]][Scorecards Link] [![SCA Icon]][SCA Link] [![Terraform SCA Icon]][Terraform SCA Link]

## 🚧 Known Issues & Limitations

### 1. Rule Priority Cannot Currently Be Managed - Solved with latest update

### 2. FM-Managed Rule Conflict for MOJ Teams - Solved with latest update

### 3. This module was created from a previous module here - https://github.com/ministryofjustice/modernisation-platform-terraform-waf

---

## Usage

This module offers various WAF rules as a module, custom ones such as IP Address blocking from an ssm parameter, as well as AWS managed ones.

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
}



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

  application_name = local.application_name        
  tags             = local.tags

}

```
<!--- BEGIN_TF_DOCS --->


<!--- END_TF_DOCS --->

## Looking for issues?
If you're looking to raise an issue with this module, please create a new issue in the [Modernisation Platform repository](https://github.com/ministryofjustice/modernisation-platform/issues).

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.0.1 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 5.90 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | ~> 5.90 |
| <a name="provider_aws.modernisation-platform"></a> [aws.modernisation-platform](#provider\_aws.modernisation-platform) | ~> 5.90 |
| <a name="provider_null"></a> [null](#provider\_null) | n/a |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_pagerduty_core_alerts"></a> [pagerduty\_core\_alerts](#module\_pagerduty\_core\_alerts) | github.com/ministryofjustice/modernisation-platform-terraform-pagerduty-integration | 0179859e6fafc567843cd55c0b05d325d5012dc4 |

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_log_group.mp_waf_cloudwatch_log_group](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_resource_policy.mp_waf_log_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_resource_policy) | resource |
| [aws_cloudwatch_log_subscription_filter.forward_to_core_logging](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_subscription_filter) | resource |
| [aws_cloudwatch_metric_alarm.ddos](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_iam_role.cwl_to_core_logging](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.cwl_to_core_logging_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_sns_topic.ddos_alarm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic.module_ddos_alarm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_ssm_parameter.ip_block_list](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ssm_parameter) | resource |
| [aws_wafv2_ip_set.mp_waf_ip_set](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_ip_set) | resource |
| [aws_wafv2_web_acl.mp_waf_acl](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl) | resource |
| [aws_wafv2_web_acl_association.mp_waf_acl_association](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_association) | resource |
| [aws_wafv2_web_acl_logging_configuration.mp_waf_log_config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_logging_configuration) | resource |
| [null_resource.validate_ddos_config](https://registry.terraform.io/providers/hashicorp/null/latest/docs/resources/resource) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.waf](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_kms_key.sns](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/kms_key) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |
| [aws_secretsmanager_secret.pagerduty_integration_keys](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/secretsmanager_secret) | data source |
| [aws_secretsmanager_secret_version.pagerduty_integration_keys](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/secretsmanager_secret_version) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_additional_managed_rules"></a> [additional\_managed\_rules](#input\_additional\_managed\_rules) | Additional AWS Managed Rule Groups to include in the WebACL. | <pre>list(object({<br/>    name            = string<br/>    vendor_name     = string<br/>    version         = optional(string)<br/>    override_action = optional(string) # 'none' or 'count'<br/>  }))</pre> | `[]` | no |
| <a name="input_application_name"></a> [application\_name](#input\_application\_name) | Application identifier used for naming and tagging. | `string` | n/a | yes |
| <a name="input_associated_resource_arns"></a> [associated\_resource\_arns](#input\_associated\_resource\_arns) | List of resource ARNs (e.g. ALB, CloudFront distribution) to associate with the Web ACL. | `list(string)` | `[]` | no |
| <a name="input_block_non_uk_traffic"></a> [block\_non\_uk\_traffic](#input\_block\_non\_uk\_traffic) | If true, add a WAF rule that blocks any request not originating from the United Kingdom (GB). | `bool` | `false` | no |
| <a name="input_core_logging_account_id"></a> [core\_logging\_account\_id](#input\_core\_logging\_account\_id) | Account ID for core logging | `string` | `""` | no |
| <a name="input_ddos_alarm_resources"></a> [ddos\_alarm\_resources](#input\_ddos\_alarm\_resources) | Map of resources to monitor for DDoS alarms. Each value must contain 'arn'. | <pre>map(object({<br/>    arn = string<br/>  }))</pre> | `{}` | no |
| <a name="input_ddos_rate_limit"></a> [ddos\_rate\_limit](#input\_ddos\_rate\_limit) | Requests per 5‑minute window that triggers the DDoS rate‑based block. Required when enable\_ddos\_protection = true. | `number` | n/a | yes |
| <a name="input_enable_core_logging"></a> [enable\_core\_logging](#input\_enable\_core\_logging) | Whether to enable forwarding logs to the core logging account | `bool` | `true` | no |
| <a name="input_enable_ddos_alarms"></a> [enable\_ddos\_alarms](#input\_enable\_ddos\_alarms) | Enable DDoS protection CloudWatch alarms | `bool` | `true` | no |
| <a name="input_enable_ddos_protection"></a> [enable\_ddos\_protection](#input\_enable\_ddos\_protection) | If true (default), create a Shield‑style rate‑based blocking rule at the WebACL. | `bool` | `true` | no |
| <a name="input_enable_pagerduty_integration"></a> [enable\_pagerduty\_integration](#input\_enable\_pagerduty\_integration) | Enable PagerDuty SNS integration for DDoS alarms | `bool` | `true` | no |
| <a name="input_ip_address_version"></a> [ip\_address\_version](#input\_ip\_address\_version) | IP version for the IP set (IPV4 or IPV6). | `string` | `"IPV4"` | no |
| <a name="input_log_destination_arn"></a> [log\_destination\_arn](#input\_log\_destination\_arn) | Optional ARN of an existing CloudWatch Log Group to send WAF logs to | `string` | `null` | no |
| <a name="input_log_retention_in_days"></a> [log\_retention\_in\_days](#input\_log\_retention\_in\_days) | Retention period for the WAF logs. | `number` | `365` | no |
| <a name="input_managed_rule_actions"></a> [managed\_rule\_actions](#input\_managed\_rule\_actions) | Map of AWS Managed Rule Group names to boolean flag indicating whether to block (true) or count (false). | `map(bool)` | n/a | yes |
| <a name="input_managed_rule_enforce"></a> [managed\_rule\_enforce](#input\_managed\_rule\_enforce) | When true, AWS Managed Rule Groups are set to block (override\_action = "none"). When false (default) they run in count mode. | `bool` | `false` | no |
| <a name="input_managed_rule_groups"></a> [managed\_rule\_groups](#input\_managed\_rule\_groups) | List of managed rule groups to enable. Each object supports:<br/>  * name            – (Required) Rule group name, e.g. "AWSManagedRulesCommonRuleSet".<br/>  * vendor\_name     – (Optional) Defaults to "AWS".<br/>  * override\_action – (Optional) "count" or "none". If omitted, the module uses managed\_rule\_enforce to decide.<br/>  * priority        – (Optional) Rule priority. If omitted, the module assigns priorities starting at 10. | <pre>list(object({<br/>    name            = string<br/>    vendor_name     = optional(string, "AWS")<br/>    override_action = optional(string)<br/>    priority        = optional(number)<br/>  }))</pre> | <pre>[<br/>  {<br/>    "name": "AWSManagedRulesKnownBadInputsRuleSet"<br/>  },<br/>  {<br/>    "name": "AWSManagedRulesCommonRuleSet"<br/>  },<br/>  {<br/>    "name": "AWSManagedRulesSQLiRuleSet"<br/>  },<br/>  {<br/>    "name": "AWSManagedRulesLinuxRuleSet"<br/>  },<br/>  {<br/>    "name": "AWSManagedRulesAnonymousIpList"<br/>  },<br/>  {<br/>    "name": "AWSManagedRulesBotControlRuleSet"<br/>  }<br/>]</pre> | no |
| <a name="input_managed_rule_priorities"></a> [managed\_rule\_priorities](#input\_managed\_rule\_priorities) | Map of AWS Managed Rule Group names to explicit priority integers.<br/>Lower numbers are evaluated first (higher priority).<br/>If omitted for a rule, a sensible default order is used (10,20,30…). | `map(number)` | `{}` | no |
| <a name="input_ssm_parameter_name"></a> [ssm\_parameter\_name](#input\_ssm\_parameter\_name) | Name of the SSM SecureString parameter that stores the JSON‑encoded blocked IP list. | `string` | `"/waf/ip_block_list"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Common tags applied to all resources. | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_ddos_alarm_sns_topic_name"></a> [ddos\_alarm\_sns\_topic\_name](#output\_ddos\_alarm\_sns\_topic\_name) | Name of the SNS topic for DDoS alarms used in PagerDuty module |
| <a name="output_ddos_alarm_topic_arn"></a> [ddos\_alarm\_topic\_arn](#output\_ddos\_alarm\_topic\_arn) | ARN of the SNS topic used for DDoS alarms |
| <a name="output_ip_set_arn"></a> [ip\_set\_arn](#output\_ip\_set\_arn) | ARN of the IP set used for blocking. |
| <a name="output_log_group_name"></a> [log\_group\_name](#output\_log\_group\_name) | Name of the CloudWatch log group containing WAF logs. |
| <a name="output_waf_log_group_arn"></a> [waf\_log\_group\_arn](#output\_waf\_log\_group\_arn) | ARN of the log group receiving WAF logs |
| <a name="output_web_acl_arn"></a> [web\_acl\_arn](#output\_web\_acl\_arn) | ARN of the WAFv2 Web ACL. |
| <a name="output_web_acl_name"></a> [web\_acl\_name](#output\_web\_acl\_name) | Name of the WAF Web ACL |
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
