# Test Lambda functions with various function URL authentication configurations
# These functions test the deny_lambda_auth_type_none SCP analysis engine

# Function 1: Lambda function with NONE authentication (violation)
resource "aws_lambda_function" "public_function_url" {
  provider      = aws.shared_foo_bar
  function_name = "test-public-function-url"
  role          = aws_iam_role.lambda_test_role.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  filename      = "${path.module}/test_deny_lambda_auth_type_none/lambda_function.zip"

  source_code_hash = filebase64sha256("${path.module}/test_deny_lambda_auth_type_none/lambda_function.zip")
}

resource "aws_lambda_function_url" "public_function_url" {
  provider           = aws.shared_foo_bar
  function_name      = aws_lambda_function.public_function_url.function_name
  authorization_type = "NONE"
}

# Function 2: Lambda function with AWS_IAM authentication (compliant)
resource "aws_lambda_function" "secure_function_url" {
  provider      = aws.shared_foo_bar
  function_name = "test-secure-function-url"
  role          = aws_iam_role.lambda_test_role.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  filename      = "${path.module}/test_deny_lambda_auth_type_none/lambda_function.zip"

  source_code_hash = filebase64sha256("${path.module}/test_deny_lambda_auth_type_none/lambda_function.zip")
}

resource "aws_lambda_function_url" "secure_function_url" {
  provider           = aws.shared_foo_bar
  function_name      = aws_lambda_function.secure_function_url.function_name
  authorization_type = "AWS_IAM"
}

# Function 3: Lambda function without function URL (compliant)
resource "aws_lambda_function" "no_function_url" {
  provider      = aws.shared_foo_bar
  function_name = "test-no-function-url"
  role          = aws_iam_role.lambda_test_role.arn
  handler       = "index.handler"
  runtime       = "python3.11"
  filename      = "${path.module}/test_deny_lambda_auth_type_none/lambda_function.zip"

  source_code_hash = filebase64sha256("${path.module}/test_deny_lambda_auth_type_none/lambda_function.zip")
}

# IAM role for Lambda functions (minimal permissions)
resource "aws_iam_role" "lambda_test_role" {
  provider = aws.shared_foo_bar
  name     = "test-lambda-auth-type-none-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Attach basic Lambda execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  provider   = aws.shared_foo_bar
  role       = aws_iam_role.lambda_test_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
