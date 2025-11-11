###############################################################################
#  Outputs
###############################################################################

# The ARN of the deployed Web ACL
output "web_acl_arn" {
  description = "ARN of the WAFv2 Web ACL."
  value       = aws_wafv2_web_acl.mp_waf_acl.arn
}

# Name of the Web ACL resource (effective name used)
output "web_acl_name" {
  description = "Name of the WAF Web ACL."
  value       = aws_wafv2_web_acl.mp_waf_acl.name
}

# ARN of the IP set used for blocking IPs
output "ip_set_arn" {
  description = "ARN of the IP set used for blocking."
  value       = aws_wafv2_ip_set.mp_waf_ip_set.arn
}

# Name of the CloudWatch log group when the module creates it; null if a custom destination ARN is supplied
output "log_group_name" {
  description = "Name of the CloudWatch log group containing WAF logs (null if log_destination_arn was provided)."
  value       = var.log_destination_arn == null ? aws_cloudwatch_log_group.mp_waf_cloudwatch_log_group[0].name : null
}

# ARN of the WAF logging destination (either custom or auto-created)
output "waf_log_group_arn" {
  description = "ARN of the log group receiving WAF logs."
  value       = var.log_destination_arn != null ? var.log_destination_arn : aws_cloudwatch_log_group.mp_waf_cloudwatch_log_group[0].arn
}

# ARN of the SNS topic used for DDoS alarms (main one)
output "ddos_alarm_topic_arn" {
  description = "ARN of the SNS topic used for DDoS alarms."
  value       = try(aws_sns_topic.ddos_alarm[0].arn, null)
}

# Name of the SNS topic for DDoS alarms used in PagerDuty module (if that topic is created)
output "ddos_alarm_sns_topic_name" {
  description = "Name of the DDoS alarms SNS topic used by the PagerDuty integration module."
  value       = var.enable_ddos_alarms && length(aws_sns_topic.module_ddos_alarm) > 0 ? aws_sns_topic.module_ddos_alarm[0].name : null
}

# Name of waf created
output "effective_web_acl_name" {
  description = "The effective Web ACL name used by the module."
  value       = local.effective_web_acl_name
}
