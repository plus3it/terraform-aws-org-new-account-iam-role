variable "assume_role_name" {
  description = "Name of IAM role to assume the target account (case sensitive)"
  type        = string
}

variable "role_name" {
  description = "Name of the IAM role to create in the target account (case sensitive)"
  type        = string
}

variable "role_permission_policy" {
  description = "AWS-managed permission policy name to attach to the role (case sensitive)"
  type        = string
}

variable "trust_policy_json" {
  description = "JSON-formatted string containing the role trust policy"
  type        = string
}

variable "lambda" {
  description = "Map of any additional arguments for the upstream lambda module. See <https://github.com/terraform-aws-modules/terraform-aws-lambda>"
  type        = any
  default     = {}
}

variable "log_level" {
  default     = "info"
  description = "Log level of the lambda output, one of: debug, info, warning, error, critical"
  type        = string
}

variable "tags" {
  default     = {}
  description = "Tags that are passed to resources"
  type        = map(string)
}
