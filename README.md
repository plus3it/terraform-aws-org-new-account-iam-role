# terraform-aws-org-new-account-iam-role

A Terraform module to bootstrap a cross-account IAM Role into an AWS 
Account that can be used when new accounts are created within AWS 
Organizations.

This module creates a new IAM role, attaches an AWS-managed permission 
policy, and uses the provided JSON-formatted string to create the trust 
relationship between an assumed role and a second account within an 
AWS Organization. 

This module uses CloudWatch Events to identify when new accounts are
added or invited to an AWS Organization, and triggers a Lambda function
to create the cross-account IAM role.

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
| log\_level | Log level of the lambda output, one of: debug, info, warning, error, critical | `string` | `"Info"` | no |

## Outputs

| Name | Description |
|------|-------------|
| aws\_cloudwatch\_event\_rule | The cloudwatch event rule object |
| aws\_cloudwatch\_event\_target | The cloudWatch event target object |
| aws\_lambda\_permission\_events | The lambda permission object for cloudwatch event triggers |
| lambda | The lambda module object |

<!-- END TFDOCS -->
