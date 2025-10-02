# Modernisation Platform Terraform Module Template 

[![Standards Icon]][Standards Link] [![Format Code Icon]][Format Code Link] [![Scorecards Icon]][Scorecards Link] [![SCA Icon]][SCA Link] [![Terraform SCA Icon]][Terraform SCA Link]

## 🚧 Known Issues & Limitations

### 1. Rule Priority Cannot Currently Be Managed - Solved with latest update

### 2. FM-Managed Rule Conflict for MOJ Teams - Solved with latest update


---

## Usage

This module offers various WAF rules as a module, custom ones such as IP Address blocking from an ssm parameter, as well as AWS managed ones.

With the `managed_rule_actions` if the bool is true, it will block traffic, false will leave it in a count mode.

You can pass in more AWS rules with `additional_managed_rules` like the example below.

For `associated_resource_arns` you can supply one or multiple ones.

For `enable_ddos_protection` it covers what is currently offered in the FM module.


```hcl

module "waf" {
  source                   = "git::https://github.com/ministryofjustice/modernisation-platform-terraform-waf?ref=ecc855f212ce6a2f36a7a77e78c42d968f15ee8d"
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
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | ~> 1.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 6.0 |

## Providers

No providers.

## Modules

No modules.

## Resources

No resources.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_application_name"></a> [application\_name](#input\_application\_name) | Name of application | `string` | n/a | yes |
| <a name="input_tags"></a> [tags](#input\_tags) | Common tags to be used by all resources | `map(string)` | n/a | yes |

## Outputs

No outputs.
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
