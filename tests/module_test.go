package testing

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AwsRegion represents a testable AWS region.
const AwsRegion = "us-east-1"

// AssumeRoleName is used for one of the required Lambda variables
// (assume_role_name) and represents the target account for the IAM role.
const AssumeRoleName = "000000000000"

// RoleName is used for one of the required Lambda variables (role_name)
// and represents a role created by the Lambda.
const RoleName = "TEST_NEW_ACCOUNT_IAM_ROLE"

// RolePermissionPolicy is one of the required Lambda variables
// (role_permission_policy) and represents an AWS-managed permission policy
// name to attach to the role.
const RolePermissionPolicy = "ReadOnlyAccess"

// LocalEndpoints provide LocalStack endpoints for AWS services required for
// the installation.
var LocalEndpoints = map[string]string{
	"cloudwatch":       "http://localhost:4566",
	"cloudwatchevents": "http://localhost:4566",
	"cloudwatchlogs":   "http://localhost:4566",
	"lambda":           "http://localhost:4566",
	"iam":              "http://localhost:4566",
	"sts":              "http://localhost:4566",
}

// Policy represents the structure of a simple policy used by one of the
// required Lambda variables (trust_policy_json).
type Policy struct {
	Version   string `json:"Version"`
	Statement []struct {
		Effect    string `json:"Effect"`
		Principal struct {
			AWS string `json:"AWS"`
		} `json:"Principal"`
		Action string `json:"Action"`
	} `json:"Statement"`
}

// createPolicy generates a simple policy in a JSON-formatted string.
func createPolicy(t *testing.T) string {
	policyString := `
	{
		"Version": "2012-10-17",
		"Statement": [{
			"Action": "sts:AssumeRole",
			"Principal": {"AWS": "arn:aws:iam::000000000000:root"},
			"Effect": "Allow"
		}]
	}`

	// Convert the string to a structure representing the JSON.
	var policy Policy
	err := json.Unmarshal([]byte(policyString), &policy)
	if err != nil {
		t.Fatal(err)
	}

	// Take that structure and convert it to series of bytes.  This
	// elminates newlines that would have been in the original string.
	bytes, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}

	// Convert those bytes into a string representation.
	return string(bytes)
}

// TestNewIamRole invokes the Terrform init/plan/apply commands and
// verifies the resulting output.  The Lambda is also invoked to verify
// the installation.
func TestNewIamRole(t *testing.T) {
	t.Parallel()

	// Use LocalStack endpoints.
	aws.SetAwsEndpointsOverrides(LocalEndpoints)

	terraformOptions := &terraform.Options{
		TerraformDir: "../",
		Vars: map[string]interface{}{
			"assume_role_name":       AssumeRoleName,
			"role_name":              RoleName,
			"role_permission_policy": RolePermissionPolicy,
			"trust_policy_json":      createPolicy(t),
		},
		EnvVars: map[string]string{
			"AWS_DEFAULT_REGION": AwsRegion,
		},
	}

	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)

	validateOutput(t, terraformOptions)

	// Extract the Lambda function name as that will be needed for
	// verifying the output and invoking the function.
	lambda_output := terraform.OutputMap(t, terraformOptions, "lambda")
	assert.NotNil(t, lambda_output)

	validateExecution(t, lambda_output["function_name"])
}

// validateOutput verifies that at least one field of each of the resource
// outputs match the expected value.
func validateOutput(t *testing.T, terraformOptions *terraform.Options) {
	lambda_output := terraform.OutputMap(t, terraformOptions, "lambda")
	assert.True(t, strings.HasPrefix(lambda_output["function_name"],
		"new_account_iam_role"))

	event_rule_output := terraform.OutputMap(t, terraformOptions,
		"aws_cloudwatch_event_rule")
	assert.True(t, strings.HasPrefix(event_rule_output["name"],
		"new_account_iam_role"))

	event_target_output := terraform.OutputMap(t, terraformOptions,
		"aws_cloudwatch_event_target")
	assert.True(t, strings.HasPrefix(event_target_output["rule"],
		"new_account_iam_role"))

	permission_events_output := terraform.OutputMap(t, terraformOptions,
		"aws_lambda_permission_events")
	assert.True(t, strings.HasPrefix(
		permission_events_output["function_name"],
		"new_account_iam_role"))
}

// Event represents the event structure passed to the Lambda handler.
// It's probably not necessary to create the event to this level of detail
// for this test, but this structure does have most of the required fields
// for the event and it provides an example of how to create an event struct.
type Event struct {
	Version    string   `json:"version"`
	ID         string   `json:"id"`
	DetailType string   `json:"detail-type"`
	Source     string   `json:"source"`
	AccountId  string   `json:"account"`
	Timestamp  string   `json:"time"`
	Region     string   `json:"region"`
	Resources  []string `json:"resources"`
	Detail     struct {
		EventName        string `json:"eventName"`
		EventSource      string `json:"eventSource"`
		ResponseElements struct {
			CreateAccountStatus struct {
				ID string `json:"id"`
			} `json:"createAccountStatus"`
		} `json:"responseElements"`
	} `json:"detail"`
}

// createEvent creates a structure representing a test event that is passed
// to the Lambda handler upon invocation.
func createEvent(t *testing.T) *Event {
	// An Event struct could have been initialized here, but this
	// shows how a JSON string would be handled.
	eventJsonString := `
	{
		"version": "0",
		"id": "66941d9a-e4d7-5e1d-3dec-d4407c159d8c",
		"detail-type": "AWS API Call via CloudTrail",
		"source": "aws.organizations",
		"account": "222222222222",
		"time": "2021-02-08T16:08:43Z",
		"region": "us-east-1",
		"resources": [],
		"detail": {
			"eventName": "CreateAccount",
			"eventSource": "organizations.amazonaws.com",
			"responseElements": {
				"createAccountStatus": {
					"id": "xxx-111111111111111111111"
				}
			}
		}
	}`
	var event Event
	err := json.Unmarshal([]byte(eventJsonString), &event)
	if err != nil {
		t.Fatal(err)
	}
	return &event
}

// validateExecution attempts to invoke the Lambda with a bad event.  The
// Lambda should return the expected exception type and message.  The
// expected exception should prove that the Lambda and the AWS powertools
// library have been installed.  (The AWS powertools library is invoked to
// log exceptions.)
func validateExecution(t *testing.T, functionName string) {
	event := createEvent(t)
	response, err := aws.InvokeFunctionE(t, AwsRegion, functionName, event)

	// If the lambda successfully responded, the status code should be 200.
	functionError, ok := err.(*aws.FunctionError)
	require.True(t, ok)
	assert.Equal(t, int(functionError.StatusCode), 200)

	// Verify the error type and message are what is expected.
	type responseMessage struct {
		ErrorMessage string   `json:"errorMessage"`
		ErrorType    string   `json:"errorType"`
		StackTrace   []string `json:"stackTrace"`
	}
	var rsp responseMessage
	err = json.Unmarshal([]byte(response), &rsp)
	if err != nil {
		require.Nil(t, err)
	}

	assert.NotNil(t, rsp.ErrorType)
	assert.Equal(t, rsp.ErrorType, "InvocationException")

	assert.NotNil(t, rsp.ErrorMessage)
	assert.Contains(t, rsp.ErrorMessage,
		`An error occurred (UnrecognizedClientException) when calling `+
			`the DescribeCreateAccountStatus operation`)
}
