# Test Infrastructure: deny_lambda_auth_type_none

## Purpose

This test infrastructure creates Lambda functions with various function URL authentication configurations to test the `deny_lambda_auth_type_none` SCP check.

## Resources Created

### Lambda Functions

1. **test-public-function-url** (Violation)
   - Lambda function with a function URL configured
   - Authorization type: `NONE` (public access)
   - This is a violation of the SCP policy

2. **test-secure-function-url** (Compliant)
   - Lambda function with a function URL configured
   - Authorization type: `AWS_IAM` (requires IAM authentication)
   - This is compliant with the SCP policy

3. **test-no-function-url** (Compliant)
   - Lambda function without a function URL
   - This is compliant with the SCP policy (no function URL exists)

### IAM Role

- **test-lambda-auth-type-none-role**: Minimal execution role for Lambda functions
  - Allows Lambda service to assume the role
  - Attached policy: `AWSLambdaBasicExecutionRole` (for CloudWatch Logs)

## Expected Check Results

When running the `deny_lambda_auth_type_none` check:

- **Violations**: 1 (test-public-function-url)
- **Compliant**: 2 (test-secure-function-url, test-no-function-url)
- **Compliance Percentage**: 66.7%

## AWS Costs

### Monthly Cost Estimate

| Resource | Configuration | Estimated Cost |
|----------|--------------|----------------|
| Lambda Functions (3) | No invocations | $0.00 |
| Lambda Function URLs (2) | No requests | $0.00 |

**Total Estimated Monthly Cost: $0.00**

Lambda functions with no invocations and function URLs with no requests have zero cost.

### Notes

- Lambda free tier includes 1M free requests and 400,000 GB-seconds of compute time per month
- These test functions should not be invoked during testing
- Function URLs have no additional charges beyond the Lambda invocation costs

## Cleanup

To remove these test resources:

```bash
cd test_environment
terraform destroy -target=aws_lambda_function.public_function_url
terraform destroy -target=aws_lambda_function.secure_function_url
terraform destroy -target=aws_lambda_function.no_function_url
terraform destroy -target=aws_iam_role.lambda_test_role
```

Or remove the entire test environment:

```bash
terraform destroy
```

## SCP Policy

The SCP being tested denies Lambda function URL creation/updates with `NONE` authentication:

```json
{
  "Sid": "DenyPublicFunctionUrls",
  "Effect": "Deny",
  "Action": [
    "lambda:CreateFunctionUrlConfig",
    "lambda:UpdateFunctionUrlConfig",
    "lambda:AddPermission"
  ],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "lambda:FunctionUrlAuthType": "NONE"
    }
  }
}
```

Once this SCP is deployed, attempts to create function URLs with `NONE` authentication will be denied.
