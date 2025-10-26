output "role_arn" {
  description = "ARN of the created Headroom role"
  value       = aws_iam_role.headroom.arn
}

output "role_name" {
  description = "Name of the created Headroom role"
  value       = aws_iam_role.headroom.name
}
