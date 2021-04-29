# terraform-aws-org-new-account-iam-role

A Terraform module to bootstrap the creation of an IAM Role in an AWS
Account when new accounts are created within AWS Organizations.

This module creates a new IAM role, attaches an AWS-managed permission
policy, and sets the trust policy to the provided JSON-formatted string.

This module uses CloudWatch Events to identify when new accounts are
added or invited to an AWS Organization, and triggers a Lambda function
to create the IAM role.

## Testing

To set up and run tests against the Terraform configuration:

```
# Start up LocalStack, a mock AWS stack:
make localstack/up

# Run the tests:
make terraform/pytest

# Shut down LocalStack and clean up docker images:
make localstack/clean
```

<!-- BEGIN TFDOCS -->
## Requirements

| Name | Version |
|------|---------|
| terraform | >= 0.12 |

## Providers

| Name | Version |
|------|---------|
| aws | n/a |
| random | n/a |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| assume\_role\_name | Name of IAM role to assume the target account (case sensitive) | `string` | n/a | yes |
| role\_name | Name of the IAM role to create in the target account (case sensitive) | `string` | n/a | yes |
| role\_permission\_policy | AWS-managed permission policy name to attach to the role (case sensitive) | `string` | n/a | yes |
| trust\_policy\_json | JSON-formatted string containing the role trust policy | `string` | n/a | yes |
| localstack\_host | FOR TESTING ONLY:  Hostname for localstack endpoint | `string` | `"localhost"` | no |
| log\_level | Log level of the lambda output, one of: debug, info, warning, error, critical | `string` | `"info"` | no |

## Outputs

| Name | Description |
|------|-------------|
| aws\_cloudwatch\_event\_rule | The cloudwatch event rule object |
| aws\_cloudwatch\_event\_target | The cloudWatch event target object |
| aws\_lambda\_permission\_events | The lambda permission object for cloudwatch event triggers |
| lambda | The lambda module object |

<!-- END TFDOCS -->
