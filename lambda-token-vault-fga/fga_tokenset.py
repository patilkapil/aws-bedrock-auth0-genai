"""
AWS Lambda function for processing Bedrock agent requests with DynamoDB session storage.
Integrates with FGA for authorization and Okta API for user group retrieval.
"""

import boto3
import json
import logging
import os
from http import HTTPStatus
from typing import Any, Dict

import requests

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize AWS DynamoDB resource
dynamodb = boto3.resource('dynamodb')

# Environment variables for configuration
# These should be set in your Lambda environment for security and flexibility
SESSION_TABLE_NAME = os.getenv("SESSION_TABLE_NAME", "bedrock-sessions")
FGA_AUTHORIZER_FUNCTION_NAME = os.getenv("FGA_AUTHORIZER_FUNCTION_NAME", "fga_authorizer-bedrock-aws-okta")
OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "https://your-okta-domain.oktapreview.com")
DEFAULT_OBJECT = os.getenv("DEFAULT_OBJECT", "okta:groups")
DEFAULT_RELATION = os.getenv("DEFAULT_RELATION", "read_okta")


def get_session_data(session_id: str):
    """
    Retrieve session data from DynamoDB.
    
    This function fetches user session information including tokens and user metadata
    that were stored during the authentication process.
    """
    table = dynamodb.Table(SESSION_TABLE_NAME)
    logger.info("Retrieving session data for session_id: %s", session_id)
    
    # Query DynamoDB for the session record
    response = table.get_item(Key={'session_id': session_id})
    item = response.get('Item')
    
    if item:
        # Remove TTL field from response (not needed by caller)
        item.pop('ttl', None)
        return item
    return None


def get_federated_token(session_id: str):
    """
    Get the federated token from session data.
    
    The federated token is used to make API calls to external services like Okta
    on behalf of the authenticated user.
    """
    session_data = get_session_data(session_id)
    return session_data.get('federated_token') if session_data else None


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler for processing Bedrock agent requests.
    
    Flow:
    1. Extract session ID from Bedrock agent session attributes
    2. Retrieve federated token from DynamoDB session storage
    3. Check FGA authorization for the requesting user
    4. If authorized, call Okta API to retrieve user groups
    5. Return formatted response for Bedrock agent

    Args:
        event: The Lambda event containing action details
        context: The Lambda context object

    Returns:
        Response containing the action execution results

    Raises:
        KeyError: If required fields are missing from the event
    """
    try:
        logger.info("Processing Bedrock agent request: %s", event)
        
        # Extract required fields from Bedrock agent event
        action_group = event['actionGroup']       # The action group being invoked
        function = event['function']              # The specific function being called
        message_version = event.get('messageVersion', 1)  # Protocol version
        parameters = event.get('parameters', [])  # Function parameters (e.g., user email)
        session_attributes = event.get("sessionAttributes", {})  # Session data from Bedrock

        # Get session ID from Bedrock session attributes
        # This was set during the authentication flow in the main application
        session_id = session_attributes['session_id']
        logger.info("Processing request for session_id: %s", session_id)
        
        # Retrieve session data and federated token from DynamoDB
        # The session contains user info and tokens stored during login
        session_data = get_session_data(session_id)
        federated_token = get_federated_token(session_id)

        # Prepare FGA authorization request
        # Check if the logged-in user has permission to read Okta groups
        invoke_fga_authz = {
            "user": session_attributes['logged_in_user'],  # Current user making the request
            "object": DEFAULT_OBJECT,                      # Resource being accessed (okta:groups)
            "relation": DEFAULT_RELATION                   # Permission being checked (read_okta)
        }

        # Invoke FGA authorizer Lambda function
        # This will check if the user has the required permissions
        lambda_client = boto3.client('lambda')
        fga_response = lambda_client.invoke(
            FunctionName=FGA_AUTHORIZER_FUNCTION_NAME,
            InvocationType='RequestResponse',  # Synchronous call
            Payload=json.dumps(invoke_fga_authz)
        )

        # Parse FGA authorization response
        response_payload = fga_response['Payload'].read()
        decoded_response = json.loads(response_payload)
        logger.info("FGA authorization result: %s", decoded_response)
        
        # Check if user is authorized to proceed
        if decoded_response['isAuthorized'] == True:
            # User is authorized - proceed with Okta API call
            if parameters[0]['value'] != "user":
                # Extract API token and target user email from parameters
                api_token = federated_token              # Token for Okta API authentication
                email = parameters[0]['value']           # Target user whose groups to retrieve

                # Set up headers for Okta API requests
                headers = {
                    'Authorization': f'Bearer {api_token}',
                    'Accept': 'application/json'
                }
                
                # Step 1: Retrieve user by email from Okta
                user_url = f'{OKTA_DOMAIN}/api/v1/users/{email}'
                user_response = requests.get(user_url, headers=headers)
                logger.info("User response status: %s", user_response.status_code)

                if user_response.status_code != 200:
                    # Handle user lookup failure
                    logger.error("Error retrieving user: %s - %s", user_response.status_code, user_response.text)
                    actiongroup_output = f"Error retrieving user: {user_response.status_code}"
                else:
                    # User found - extract user ID for groups lookup
                    user = user_response.json()
                    user_id = user['id']
                    logger.info("User ID: %s", user_id)
                    
                    # Step 2: Retrieve user's groups from Okta
                    groups_url = f'{OKTA_DOMAIN}/api/v1/users/{user_id}/groups'
                    groups_response = requests.get(groups_url, headers=headers)

                    if groups_response.status_code != 200:
                        # Handle groups lookup failure
                        logger.error("Error retrieving groups: %s - %s", groups_response.status_code, groups_response.text)
                        actiongroup_output = f"Error retrieving groups: {groups_response.status_code}"
                    else:
                        # Groups retrieved successfully - format response
                        groups = groups_response.json()
                        logger.info("Retrieved %d groups for user", len(groups))
                        
                        # Build comma-separated list of group names
                        actiongroup_output = ""
                        for group in groups:
                            group_name = group['profile']['name']
                            logger.info("Group: %s", group_name)
                            actiongroup_output += group_name + ","
                        
                        # Remove trailing comma if present
                        actiongroup_output = actiongroup_output.rstrip(',')
            else:
                # Invalid parameter provided
                actiongroup_output = "No valid user parameter provided"
        else:
            # User is not authorized to perform this action
            actiongroup_output = "You are not authorized to perform this action"
            
        # Prepare response in Bedrock agent format
        # This follows the required structure for Bedrock agent responses
        response_body = {
            'TEXT': {
                'body': actiongroup_output,    # The actual response content
                'contentType': 'text/plain'    # Content type for the response
            }
        }
        
        # Wrap response body in action response structure
        action_response = {
            'actionGroup': action_group,
            'function': function,
            'functionResponse': {
                'responseBody': response_body
            }
        }
        
        # Final response structure for Bedrock agent
        response = {
            'response': action_response,
            'messageVersion': message_version
        }

        logger.info('Response: %s', response)
        return response

    except KeyError as e:
        # Handle missing required fields in the event
        logger.error('Missing required field: %s', str(e))
        return {
            'statusCode': HTTPStatus.BAD_REQUEST,
            'body': f'Error: {str(e)}'
        }
    except Exception as e:
        # Handle any unexpected errors
        logger.error('Unexpected error: %s', str(e))
        return {
            'statusCode': HTTPStatus.INTERNAL_SERVER_ERROR,
            'body': 'Internal server error'
        }
