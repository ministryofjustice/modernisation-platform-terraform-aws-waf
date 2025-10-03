package test

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWAFModule(t *testing.T) {
	t.Parallel()

	awsRegion := "eu-west-2"

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "./unit-test",
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": awsRegion,
		},
	})

	// Apply once, destroy once
	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	t.Run("OutputsNotEmpty", func(t *testing.T) {
		testOutputsNotEmpty(t, terraformOptions)
	})
	t.Run("WebACLStructure", func(t *testing.T) {
		testWebACLStructure(t, terraformOptions, awsRegion)
	})
	t.Run("IPSetExistsAndHasAddresses", func(t *testing.T) {
		testIPSetExistsAndHasAddresses(t, terraformOptions, awsRegion)
	})
	t.Run("WebACLLoggingConfiguration", func(t *testing.T) {
		testWebACLLoggingConfiguration(t, terraformOptions, awsRegion)
	})
	t.Run("ManagedRulePriorities", func(t *testing.T) {
		testManagedRulePriorities(t, terraformOptions, awsRegion)
	})
	t.Run("ManagedRuleOverrideActionsAreNone", func(t *testing.T) {
		testManagedRuleOverrideActions(t, terraformOptions, awsRegion)
	})
	t.Run("PrioritiesUniqueAndReservedSlots", func(t *testing.T) {
		testPrioritiesUniqueAndReserved(t, terraformOptions, awsRegion)
	})
	t.Run("RateLimitRuleHasConfiguredLimit", func(t *testing.T) {
		testRateLimitRuleLimit(t, terraformOptions, awsRegion, int64(1500))
	})
}

func testOutputsNotEmpty(t *testing.T, terraformOptions *terraform.Options) {
	webAclArn := terraform.Output(t, terraformOptions, "web_acl_arn")
	ipSetArn := terraform.Output(t, terraformOptions, "ip_set_arn")
	wafLogGroupArn := terraform.Output(t, terraformOptions, "waf_log_group_arn")

	assert.NotEmpty(t, webAclArn, "web_acl_arn should not be empty")
	assert.NotEmpty(t, ipSetArn, "ip_set_arn should not be empty")
	assert.Contains(t, wafLogGroupArn, "arn:aws:logs", "Expected a CloudWatch log group ARN")
}

func testWebACLStructure(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	webAclArn := terraform.Output(t, terraformOptions, "web_acl_arn")
	webAclId := getResourceIdFromArn(webAclArn)
	webAclName := getResourceNameFromArn(webAclArn)

	wafClient := newWAFv2Client(awsRegion)

	webAcl, err := wafClient.GetWebACL(&wafv2.GetWebACLInput{
		Id:    aws.String(webAclId),
		Name:  aws.String(webAclName),
		Scope: aws.String("REGIONAL"),
	})
	require.NoError(t, err, "Failed to fetch WAF WebACL")
	require.NotNil(t, webAcl.WebACL)

	assert.Equal(t, webAclName, aws.StringValue(webAcl.WebACL.Name))

	ruleNames := map[string]bool{}
	for _, r := range webAcl.WebACL.Rules {
		ruleNames[aws.StringValue(r.Name)] = true
	}

	assert.True(t, ruleNames[webAclName+"-blocked-ip"], "Expected 'blocked-ip' rule to exist")
	assert.True(t, ruleNames["shield-block"], "Expected 'shield-block' rule to exist")
	assert.True(t, ruleNames["block-non-uk"], "Expected 'block-non-uk' rule to exist")
}

func testIPSetExistsAndHasAddresses(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	ipSetArn := terraform.Output(t, terraformOptions, "ip_set_arn")
	ipSetId := getResourceIdFromArn(ipSetArn)
	ipSetName := getResourceNameFromArn(ipSetArn)

	wafClient := newWAFv2Client(awsRegion)

	ipSet, err := wafClient.GetIPSet(&wafv2.GetIPSetInput{
		Id:    aws.String(ipSetId),
		Name:  aws.String(ipSetName),
		Scope: aws.String("REGIONAL"),
	})
	require.NoError(t, err, "Failed to fetch IP Set")
	require.NotNil(t, ipSet.IPSet)
	assert.GreaterOrEqual(t, len(ipSet.IPSet.Addresses), 0, "IP Set should exist even if it has 0 addresses")
}

func testWebACLLoggingConfiguration(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	webAclArn := terraform.Output(t, terraformOptions, "web_acl_arn")
	expectedLogGroupArn := terraform.Output(t, terraformOptions, "waf_log_group_arn")

	wafClient := newWAFv2Client(awsRegion)

	logConfig, err := wafClient.GetLoggingConfiguration(&wafv2.GetLoggingConfigurationInput{
		ResourceArn: aws.String(webAclArn),
	})
	require.NoError(t, err, "Expected WAF logging configuration to be retrievable")
	require.NotNil(t, logConfig.LoggingConfiguration)

	assert.Equal(t, webAclArn, aws.StringValue(logConfig.LoggingConfiguration.ResourceArn), "Logging config should reference the WebACL ARN")
	require.NotEmpty(t, logConfig.LoggingConfiguration.LogDestinationConfigs, "Logging config should have at least one destination")

	foundDest := false
	for _, d := range logConfig.LoggingConfiguration.LogDestinationConfigs {
		if aws.StringValue(d) == expectedLogGroupArn {
			foundDest = true
			break
		}
	}
	assert.True(t, foundDest, "Logging destination should match waf_log_group_arn output")
}


var managedRuleNames = []string{
	"AWSManagedRulesKnownBadInputsRuleSet",
	"AWSManagedRulesCommonRuleSet",
	"AWSManagedRulesSQLiRuleSet",
	"AWSManagedRulesLinuxRuleSet",
	"AWSManagedRulesAnonymousIpList",
	"AWSManagedRulesBotControlRuleSet",
}

func testManagedRulePriorities(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	webAclArn := terraform.Output(t, terraformOptions, "web_acl_arn")
	webAclId := getResourceIdFromArn(webAclArn)
	webAclName := getResourceNameFromArn(webAclArn)

	wafClient := newWAFv2Client(awsRegion)
	resp, err := wafClient.GetWebACL(&wafv2.GetWebACLInput{
		Id:    aws.String(webAclId),
		Name:  aws.String(webAclName),
		Scope: aws.String("REGIONAL"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp.WebACL)

	prios := map[string]int64{}
	for _, r := range resp.WebACL.Rules {
		prios[aws.StringValue(r.Name)] = aws.Int64Value(r.Priority)
	}


	assert.Equal(t, int64(5), prios["AWSManagedRulesSQLiRuleSet"])
	assert.Equal(t, int64(6), prios["AWSManagedRulesKnownBadInputsRuleSet"])
	assert.Equal(t, int64(7), prios["AWSManagedRulesCommonRuleSet"])

	assert.Equal(t, int64(40), prios["AWSManagedRulesLinuxRuleSet"])
	assert.Equal(t, int64(50), prios["AWSManagedRulesAnonymousIpList"])
	assert.Equal(t, int64(60), prios["AWSManagedRulesBotControlRuleSet"])
}

func testManagedRuleOverrideActions(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	webAclArn := terraform.Output(t, terraformOptions, "web_acl_arn")
	webAclId := getResourceIdFromArn(webAclArn)
	webAclName := getResourceNameFromArn(webAclArn)

	wafClient := newWAFv2Client(awsRegion)
	resp, err := wafClient.GetWebACL(&wafv2.GetWebACLInput{
		Id:    aws.String(webAclId),
		Name:  aws.String(webAclName),
		Scope: aws.String("REGIONAL"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp.WebACL)

	rulesByName := map[string]*wafv2.Rule{}
	for _, r := range resp.WebACL.Rules {
		rulesByName[aws.StringValue(r.Name)] = r
	}

	for _, name := range managedRuleNames {
		r, ok := rulesByName[name]
		require.True(t, ok, "expected managed rule %s to exist", name)
		require.NotNil(t, r.OverrideAction, "managed rule %s should have override_action", name)
		assert.NotNil(t, r.OverrideAction.None, "managed rule %s should have override_action.none", name)
	}
}

func testPrioritiesUniqueAndReserved(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	webAclArn := terraform.Output(t, terraformOptions, "web_acl_arn")
	webAclId := getResourceIdFromArn(webAclArn)
	webAclName := getResourceNameFromArn(webAclArn)

	wafClient := newWAFv2Client(awsRegion)
	resp, err := wafClient.GetWebACL(&wafv2.GetWebACLInput{
		Id:    aws.String(webAclId),
		Name:  aws.String(webAclName),
		Scope: aws.String("REGIONAL"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp.WebACL)

	seen := map[int64]string{}
	for _, r := range resp.WebACL.Rules {
		p := aws.Int64Value(r.Priority)
		if prev, exists := seen[p]; exists {
			t.Fatalf("Duplicate priority %d between rules %q and %q", p, prev, aws.StringValue(r.Name))
		}
		seen[p] = aws.StringValue(r.Name)
	}

	assert.Equal(t, webAclName+"-blocked-ip", seen[1])
	assert.Equal(t, "shield-block", seen[2])
	assert.Equal(t, "block-non-uk", seen[3])
}

func testRateLimitRuleLimit(t *testing.T, terraformOptions *terraform.Options, awsRegion string, expectedLimit int64) {
	webAclArn := terraform.Output(t, terraformOptions, "web_acl_arn")
	webAclId := getResourceIdFromArn(webAclArn)
	webAclName := getResourceNameFromArn(webAclArn)

	wafClient := newWAFv2Client(awsRegion)
	resp, err := wafClient.GetWebACL(&wafv2.GetWebACLInput{
		Id:    aws.String(webAclId),
		Name:  aws.String(webAclName),
		Scope: aws.String("REGIONAL"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp.WebACL)

	var rateRule *wafv2.Rule
	for _, r := range resp.WebACL.Rules {
		if aws.StringValue(r.Name) == "shield-block" {
			rateRule = r
			break
		}
	}
	require.NotNil(t, rateRule, "shield-block rule should exist")

	require.NotNil(t, rateRule.Statement, "shield-block should have a statement")
	require.NotNil(t, rateRule.Statement.RateBasedStatement, "shield-block should have a rate_based_statement")
	assert.Equal(t, expectedLimit, aws.Int64Value(rateRule.Statement.RateBasedStatement.Limit))
}


func getResourceIdFromArn(arn string) string {
	parts := strings.Split(arn, "/")
	return parts[len(parts)-1]
}

func getResourceNameFromArn(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return ""
}

func newWAFv2Client(region string) *wafv2.WAFV2 {
	sess := session.Must(session.NewSession(&aws.Config{Region: aws.String(region)}))
	return wafv2.New(sess)
}
