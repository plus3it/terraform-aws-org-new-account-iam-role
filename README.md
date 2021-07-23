# terraform-aws-org-new-account-iam-role

A Terraform module to bootstrap the creation of an IAM Role in an AWS
Account when new accounts are created within AWS Organizations.

This module creates a new IAM role, attaches an AWS-managed permission
policy, and sets the trust policy to the provided JSON-formatted string.

This module uses CloudWatch Events to identify when new accounts are
added or invited to an AWS Organization, and triggers a Lambda function
to create the IAM role.

## Testing

To set up and run tests:

```
# Ensure the dependencies are installed on your system.
make python/deps
make pytest/deps

# Start up a mock AWS stack:
make mockstack/up

# Run unit tests:
make docker/run target=pytest/lambda/tests

# Run tests against the Terraform configuration:
make mockstack/pytest/lambda

# Shut down the mock AWS stack and clean up the docker image:
make mockstack/clean
```

<!-- BEGIN TFDOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.12 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |
| <a name="provider_random"></a> [random](#provider\_random) | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_iam_policy_document.lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_assume_role_name"></a> [assume\_role\_name](#input\_assume\_role\_name) | Name of IAM role to assume the target account (case sensitive) | `string` | n/a | yes |
| <a name="input_role_name"></a> [role\_name](#input\_role\_name) | Name of the IAM role to create in the target account (case sensitive) | `string` | n/a | yes |
| <a name="input_role_permission_policy"></a> [role\_permission\_policy](#input\_role\_permission\_policy) | AWS-managed permission policy name to attach to the role (case sensitive) | `string` | n/a | yes |
| <a name="input_trust_policy_json"></a> [trust\_policy\_json](#input\_trust\_policy\_json) | JSON-formatted string containing the role trust policy | `string` | n/a | yes |
| <a name="input_log_level"></a> [log\_level](#input\_log\_level) | Log level of the lambda output, one of: debug, info, warning, error, critical | `string` | `"info"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags that are passed to resources | `map(string)` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_aws_cloudwatch_event_rule"></a> [aws\_cloudwatch\_event\_rule](#output\_aws\_cloudwatch\_event\_rule) | The cloudwatch event rule object |
| <a name="output_aws_cloudwatch_event_target"></a> [aws\_cloudwatch\_event\_target](#output\_aws\_cloudwatch\_event\_target) | The cloudWatch event target object |
| <a name="output_aws_lambda_permission_events"></a> [aws\_lambda\_permission\_events](#output\_aws\_lambda\_permission\_events) | The lambda permission object for cloudwatch event triggers |
| <a name="output_lambda"></a> [lambda](#output\_lambda) | The lambda module object |

<!-- END TFDOCS -->
