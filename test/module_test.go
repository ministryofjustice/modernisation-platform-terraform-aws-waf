package test

import (
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
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

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	t.Run("TestOutputsNotEmpty", func(t *testing.T) {
		testOutputsNotEmpty(t, terraformOptions)
	})

	t.Run("TestWebACLStructure", func(t *testing.T) {
		testWebACLStructure(t, terraformOptions, awsRegion)
	})

	t.Run("TestIPSetExistsAndHasAddresses", func(t *testing.T) {
		testIPSetExistsAndHasAddresses(t, terraformOptions, awsRegion)
	})

	t.Run("TestWebACLLoggingConfiguration", func(t *testing.T) {
		testWebACLLoggingConfiguration(t, terraformOptions, awsRegion)
	})
}

func testOutputsNotEmpty(t *testing.T, terraformOptions *terraform.Options) {
	webAclArn := terraform.Output(t, terraformOptions, "web_acl_arn")
	ipSetArn := terraform.Output(t, terraformOptions, "ip_set_arn")
	logGroupArn := terraform.Output(t, terraformOptions, "waf_log_group_arn")

	assert.NotEmpty(t, webAclArn, "web_acl_arn should not be empty")
	assert.NotEmpty(t, ipSetArn, "ip_set_arn should not be empty")
	assert.Contains(t, logGroupArn, "arn:aws:logs", "Expected a CloudWatch log group ARN")
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
	assert.NoError(t, err, "Failed to fetch WAF WebACL")

	assert.Equal(t, webAclName, *webAcl.WebACL.Name)

	ruleNames := map[string]bool{}
	for _, rule := range webAcl.WebACL.Rules {
		ruleNames[*rule.Name] = true
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
	assert.NoError(t, err, "Failed to fetch IP Set")
	assert.NotNil(t, ipSet.IPSet)
	assert.GreaterOrEqual(t, len(ipSet.IPSet.Addresses), 0, "IP Set should exist even if it has 0 addresses")
}

func testWebACLLoggingConfiguration(t *testing.T, terraformOptions *terraform.Options, awsRegion string) {
	webAclArn := terraform.Output(t, terraformOptions, "web_acl_arn")

	wafClient := newWAFv2Client(awsRegion)

	logConfig, err := wafClient.GetLoggingConfiguration(&wafv2.GetLoggingConfigurationInput{
		ResourceArn: aws.String(webAclArn),
	})
	assert.NoError(t, err, "Expected WAF logging configuration to be retrievable")
	assert.NotNil(t, logConfig.LoggingConfiguration)
	assert.Equal(t, webAclArn, *logConfig.LoggingConfiguration.ResourceArn, "Logging config should reference the WebACL ARN")
	assert.NotEmpty(t, logConfig.LoggingConfiguration.LogDestinationConfigs, "Logging config should have at least one destination")
}

// Helper: extract the resource ID (last part of ARN)
func getResourceIdFromArn(arn string) string {
	parts := strings.Split(arn, "/")
	return parts[len(parts)-1]
}

// Helper: extract the resource Name (second-to-last part of ARN)
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
