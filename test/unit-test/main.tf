module "waf" {
  source = "../../" # path to your root module
  providers = {
    aws.modernisation-platform = aws
  }
  enable_pagerduty_integration = false
  enable_ddos_alarms           = false
  core_logging_account_id      = local.environment_management.account_ids["testing-test"]
  enable_ddos_protection       = true
  ddos_rate_limit              = 1500
  block_non_uk_traffic         = true
  managed_rule_actions = {
    AWSManagedRulesKnownBadInputsRuleSet = false
    AWSManagedRulesCommonRuleSet         = false
    AWSManagedRulesSQLiRuleSet           = false
    AWSManagedRulesLinuxRuleSet          = false
    AWSManagedRulesAnonymousIpList       = false
    AWSManagedRulesBotControlRuleSet     = false
  }

  managed_rule_priorities = {
    AWSManagedRulesSQLiRuleSet           = 5
    AWSManagedRulesKnownBadInputsRuleSet = 6
    AWSManagedRulesCommonRuleSet         = 7
  }

  application_name    = local.application_name
  tags                = local.tags
  enable_core_logging = false
}
