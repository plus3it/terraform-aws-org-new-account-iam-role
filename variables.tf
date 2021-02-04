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
variable "trust_policy_json" {
  description = "JSON-formatted string containing the role trust policy"
  type        = string
}
variable "log_level" {
  default     = "Info"
  description = "Log level of the lambda output, one of: debug, info, warning, error, critical"
  type        = string
}
variable "aws_region" {
  description = "Region to pass to AWS Terraform provider"
  type        = string
}
