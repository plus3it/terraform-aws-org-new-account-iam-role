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
variable "log_level" {
  default     = "info"
  description = "Log level of the lambda output, one of: debug, info, warning, error, critical"
  type        = string
}
variable "localstack_host" {
  description = "FOR TESTING ONLY:  Hostname for localstack endpoint"
  type        = string
  default     = "localhost"
}
