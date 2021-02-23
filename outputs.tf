output "lambda" {
  description = "The lambda module object"
  value       = module.lambda
}

output "aws_cloudwatch_event_rule" {
  description = "The cloudwatch event rule object"
  value       = aws_cloudwatch_event_rule.this
}

output "aws_cloudwatch_event_target" {
  description = "The cloudWatch event target object"
  value       = aws_cloudwatch_event_target.this
}

output "aws_lambda_permission_events" {
  description = "The lambda permission object for cloudwatch event triggers"
  value       = aws_lambda_permission.events
}
