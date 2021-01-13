# terraform-aws-org-new-account-iam-role

A Terraform module to bootstrap IAM Roles in new AWS Accounts created through AWS Organizations

## CloudFormation Support

TBD

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
| assume\_role\_arn | ARN of IAM role to assume the target account (case sensitive) | `string` | n/a | yes |
| aws\_region | Region to pass to AWS Terraform provider | `string` | n/a | yes |
| role\_name | Name of the IAM role to create | `string` | n/a | yes |
| role\_permission\_policy | colon [:] delimited list of permission policy names to action | `string` | n/a | yes |
| role\_trust\_policy | colon [:] delimited AWS account IDs to action, or JSON policyDoc | `string` | n/a | yes |
| log\_level | Log level of the lambda output, one of: Debug, Info, Warning, Error, Critical | `string` | `"Info"` | no |
| role\_permission\_action | ['add' or 'remove'] role\_permission\_policy from role\_name | `string` | `"add"` | no |
| role\_trust\_action | ['add', 'remove', 'force'] role\_trust\_policy account IDs from role\_name | `string` | `"add"` | no |

## Outputs

| Name | Description |
|------|-------------|
| aws\_cloudwatch\_event\_rule | The cloudwatch event rule object |
| aws\_cloudwatch\_event\_target | The cloudWatch event target object |
| aws\_lambda\_permission\_events | The lambda permission object for cloudwatch event triggers |
| lambda | The lambda module object |

<!-- END TFDOCS -->
