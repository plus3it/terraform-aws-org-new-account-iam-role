variable "assume_role_arn" {
  description = "ARN of IAM role to assume the target account (case sensitive)"
  type        = string
}
variable "role_name" {
  description = "Name of the IAM role to create"
  type        = string
}
variable "role_permission_policy" {
  description = "colon [:] delimited list of permission policy names to action"
  type        = string
}
variable "role_permission_action" {
  description = "['add' or 'remove'] role_permission_policy from role_name"
  default     = "add"
  type        = string
}
variable "role_trust_policy" {
  description = "colon [:] delimited AWS account IDs to action, or JSON policyDoc"
  type        = string
}
variable "role_trust_action" {
  description = "['add', 'remove', 'force'] role_trust_policy account IDs from role_name"
  default     = "add"
  type        = string
}
variable "log_level" {
  default     = "Info"
  description = "Log level of the lambda output, one of: Debug, Info, Warning, Error, Critical"
  type        = string
}
variable "aws_region" {
  description = "Region to pass to AWS Terraform provider"
  type        = string
}
