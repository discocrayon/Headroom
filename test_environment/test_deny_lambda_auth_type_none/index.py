"""
Minimal Lambda function for testing deny_lambda_auth_type_none check.

This function does nothing useful - it exists solely for testing the SCP check.
"""


def handler(event, context):
    """
    Minimal Lambda handler.

    Args:
        event: Lambda event
        context: Lambda context

    Returns:
        Simple response
    """
    return {
        "statusCode": 200,
        "body": "Test function for deny_lambda_auth_type_none check"
    }
