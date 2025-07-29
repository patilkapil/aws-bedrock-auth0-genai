"""
AWS Lambda function for processing Bedrock agent requests with Fine-Grained Authorization.

This module provides functionality to:
- Retrieve session data from DynamoDB
- Check FGA authorization
- Integrate with Okta API for user group retrieval
- Return structured responses for Bedrock agents
"""

import json
import logging
import os
from http import HTTPStatus
from typing import Any, Dict, Optional

import boto3
import requests
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize AWS DynamoDB resource
dynamodb = boto3.resource('dynamodb')

# Environment variables with defaults
SESSION_TABLE_NAME = os.getenv("SESSION_TABLE_NAME", "bedrock-sessions")
FGA_AUTHORIZER_FUNCTION_NAME = os.getenv(
    "FGA_AUTHORIZER_FUNCTION_NAME", 
    "fga_authorizer-bedrock-aws-okta"
)
OKTA_DOMAIN = os.getenv("OKTA_DOMAIN", "https://your-okta-domain.oktapreview.com")
DEFAULT_OBJECT = os.getenv("DEFAULT_OBJECT", "okta:groups")
DEFAULT_RELATION = os.getenv("DEFAULT_RELATION", "read_okta")

# Constants
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))


class SessionNotFoundError(Exception):
    """Raised when session data is not found in DynamoDB."""
    pass


class FederatedTokenNotFoundError(Exception):
    """Raised when federated token is not found in session data."""
    pass


class AuthorizationError(Exception):
    """Raised when FGA authorization fails."""
    pass


def get_session_data(session_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve session data from DynamoDB.
    
    Args:
        session_id: The session identifier
        
    Returns:
        Session data dictionary or None if not found
        
    Raises:
        SessionNotFoundError: If session is not found in DynamoDB
    """
    if not session_id:
        raise ValueError("Session ID cannot be empty")
        
    try:
        table = dynamodb.Table(SESSION_TABLE_NAME)
        logger.info("Retrieving session data for session_id: %s", session_id)
        
        response = table.get_item(Key={'session_id': session_id})
        item = response.get('Item')
        
        if item:
            # Remove TTL field from response
            item.pop('ttl', None)
            logger.info("Successfully retrieved session data")
            return item
        else:
            logger.warning("No session data found for session_id: %s", session_id)
            raise SessionNotFoundError(f"Session {session_id} not found")
            
    except ClientError as e:
        logger.error(
            "DynamoDB error retrieving session data for session_id %s: %s", 
            session_id, 
            str(e)
        )
        raise
    except Exception as e:
        logger.error(
            "Unexpected error retrieving session data for session_id %s: %s", 
            session_id, 
            str(e)
        )
        raise


def get_federated_token(session_id: str) -> str:
    """
    Get the federated token from session data stored in DynamoDB.
    
    Args:
        session_id: The session identifier
        
    Returns:
        Federated token string
        
    Raises:
        FederatedTokenNotFoundError: If token is not found in session data
    """
    session_data = get_session_data(session_id)
    
    if session_data:
        federated_token = session_data.get('federated_token')
        if federated_token:
            logger.info("Successfully retrieved federated token from session")
            return federated_token
        else:
            logger.warning("No federated token found in session data")
            raise FederatedTokenNotFoundError("Federated token not found in session")
    
    raise FederatedTokenNotFoundError("Session data not available")


def invoke_fga_authorizer(user: str, object_name: str, relation: str) -> bool:
    """
    Invoke the FGA authorizer Lambda function to check permissions.
    
    Args:
        user: The user to check authorization for
        object_name: The object to check permissions on
        relation: The relation/permission to check
        
    Returns:
        True if authorized, False otherwise
        
    Raises:
        AuthorizationError: If authorization check fails
    """
    if not all([user, object_name, relation]):
        raise ValueError("User, object_name, and relation cannot be empty")
        
    try:
        fga_authz_payload = {
            "user": user,
            "object": object_name,
            "relation": relation
        }
        
        lambda_client = boto3.client('lambda')
        logger.info("Invoking FGA authorizer for user: %s", user)
        
        fga_response = lambda_client.invoke(
            FunctionName=FGA_AUTHORIZER_FUNCTION_NAME,
            InvocationType='RequestResponse',
            Payload=json.dumps(fga_authz_payload)
        )

        response_payload = fga_response['Payload'].read()
        decoded_response = json.loads(response_payload)
        logger.info("FGA authorization result: %s", decoded_response)
        
        return decoded_response.get('isAuthorized', False)
        
    except ClientError as e:
        logger.error("AWS error invoking FGA authorizer: %s", str(e))
        raise AuthorizationError(f"Failed to invoke FGA authorizer: {str(e)}")
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON response from FGA authorizer: %s", str(e))
        raise AuthorizationError(f"Invalid response from FGA authorizer: {str(e)}")
    except Exception as e:
        logger.error("Unexpected error invoking FGA authorizer: %s", str(e))
        raise AuthorizationError(f"Authorization check failed: {str(e)}")


def get_okta_user_groups(email: str, api_token: str) -> str:
    """
    Retrieve user groups from Okta using the provided API token.
    
    Args:
        email: The user's email address
        api_token: The federated access token for Okta API
        
    Returns:
        Comma-separated list of group names
        
    Raises:
        requests.RequestException: If Okta API request fails
        ValueError: If email or api_token is empty
    """
    if not email or not api_token:
        raise ValueError("Email and API token cannot be empty")
        
    headers = {
        'Authorization': f'Bearer {api_token}',
        'Accept': 'application/json'
    }
    
    try:
        # Retrieve user by email
        user_url = f'{OKTA_DOMAIN}/api/v1/users/{email}'
        logger.info("Retrieving user from Okta: %s", email)
        
        user_response = requests.get(
            user_url, 
            headers=headers, 
            timeout=REQUEST_TIMEOUT
        )
        user_response.raise_for_status()

        user_data = user_response.json()
        user_id = user_data['id']
        logger.info("User ID retrieved: %s", user_id)
        
        # Retrieve user's groups
        groups_url = f'{OKTA_DOMAIN}/api/v1/users/{user_id}/groups'
        logger.info("Retrieving groups for user_id: %s", user_id)
        
        groups_response = requests.get(
            groups_url, 
            headers=headers, 
            timeout=REQUEST_TIMEOUT
        )
        groups_response.raise_for_status()

        groups_data = groups_response.json()
        group_names = []
        
        logger.info("Retrieved %d groups for user", len(groups_data))
        for group in groups_data:
            group_name = group['profile']['name']
            group_names.append(group_name)
            logger.info("Group: %s", group_name)
            
        return ",".join(group_names)
        
    except requests.exceptions.Timeout:
        error_msg = f"Timeout error retrieving data for user: {email}"
        logger.error(error_msg)
        raise requests.RequestException(error_msg)
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP error retrieving data for user {email}: {e.response.status_code}"
        logger.error(error_msg)
        raise requests.RequestException(error_msg)
    except requests.exceptions.RequestException as e:
        error_msg = f"Request error retrieving data for user {email}: {str(e)}"
        logger.error(error_msg)
        raise
    except KeyError as e:
        error_msg = f"Missing expected field in Okta response: {str(e)}"
        logger.error(error_msg)
        raise ValueError(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error retrieving groups for {email}: {str(e)}"
        logger.error(error_msg)
        raise


def create_bedrock_response(
    action_group: str, 
    function: str, 
    message_version: int, 
    response_text: str
) -> Dict[str, Any]:
    """
    Create a standardized response for Bedrock agents.
    
    Args:
        action_group: The action group name
        function: The function name
        message_version: The message version
        response_text: The response text to return
        
    Returns:
        Standardized Bedrock agent response dictionary
    """
    response_body = {
        'TEXT': {
            'body': response_text,
            'contentType': 'text/plain'
        }
    }
    
    action_response = {
        'actionGroup': action_group,
        'function': function,
        'functionResponse': {
            'responseBody': response_body
        }
    }
    
    return {
        'response': action_response,
        'messageVersion': message_version
    }


def validate_event_parameters(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and extract required parameters from the event.
    
    Args:
        event: The Lambda event dictionary
        
    Returns:
        Dictionary containing validated parameters
        
    Raises:
        KeyError: If required fields are missing
        ValueError: If parameters are invalid
    """
    required_fields = ['actionGroup', 'function']
    for field in required_fields:
        if field not in event:
            raise KeyError(f"Missing required field: {field}")
    
    # Extract parameters
    action_group = event['actionGroup']
    function = event['function']
    message_version = event.get('messageVersion', 1)
    parameters = event.get('parameters', [])
    session_attributes = event.get("sessionAttributes", {})
    
    # Validate session attributes
    session_id = session_attributes.get('session_id')
    if not session_id:
        raise ValueError("session_id not found in session attributes")
        
    logged_in_user = session_attributes.get('logged_in_user')
    if not logged_in_user:
        raise ValueError("logged_in_user not found in session attributes")
    
    return {
        'action_group': action_group,
        'function': function,
        'message_version': message_version,
        'parameters': parameters,
        'session_id': session_id,
        'logged_in_user': logged_in_user
    }


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler for processing Bedrock agent requests with DynamoDB session storage.
    
    This function:
    1. Validates input parameters
    2. Retrieves session data from DynamoDB using session_id
    3. Gets federated token from session data
    4. Checks FGA authorization
    5. Calls Okta API to retrieve user groups if authorized
    
    Args:
        event: The Lambda event containing action details
        context: The Lambda context object

    Returns:
        Bedrock agent response dictionary
    """
    try:
        logger.info("Processing Bedrock agent request")
        
        # Validate and extract parameters
        params = validate_event_parameters(event)
        
        logger.info("Processing request for session_id: %s", params['session_id'])
        
        # Get federated token from session data
        try:
            federated_token = get_federated_token(params['session_id'])
        except (SessionNotFoundError, FederatedTokenNotFoundError) as e:
            logger.error("Session/token error: %s", str(e))
            return create_bedrock_response(
                params['action_group'], 
                params['function'], 
                params['message_version'], 
                "Session expired or invalid. Please log in again."
            )

        # Check FGA authorization
        try:
            is_authorized = invoke_fga_authorizer(
                params['logged_in_user'], 
                DEFAULT_OBJECT, 
                DEFAULT_RELATION
            )
        except AuthorizationError as e:
            logger.error("Authorization error: %s", str(e))
            return create_bedrock_response(
                params['action_group'], 
                params['function'], 
                params['message_version'], 
                "Authorization check failed. Please try again."
            )
        
        if is_authorized:
            # User is authorized, proceed with Okta group retrieval
            if (params['parameters'] and 
                len(params['parameters']) > 0 and 
                params['parameters'][0].get('value') != "user"):
                
                user_email = params['parameters'][0]['value']
                logger.info("Retrieving groups for user: %s", user_email)
                
                try:
                    action_output = get_okta_user_groups(user_email, federated_token)
                except (requests.RequestException, ValueError) as e:
                    logger.error("Okta API error: %s", str(e))
                    action_output = f"Error retrieving user groups: {str(e)}"
            else:
                action_output = "No valid user parameter provided"
                logger.warning("Invalid or missing user parameter")
        else:
            action_output = "You are not authorized to perform this action"
            logger.warning("User %s is not authorized for action", params['logged_in_user'])
            
        logger.info("Action completed successfully")
        return create_bedrock_response(
            params['action_group'], 
            params['function'], 
            params['message_version'], 
            action_output
        )

    except KeyError as e:
        logger.error('Missing required field: %s', str(e))
        return {
            'statusCode': HTTPStatus.BAD_REQUEST,
            'body': f'Error: Missing required field {str(e)}'
        }
    except ValueError as e:
        logger.error('Invalid parameter: %s', str(e))
        return {
            'statusCode': HTTPStatus.BAD_REQUEST,
            'body': f'Error: Invalid parameter {str(e)}'
        }
    except Exception as e:
        logger.error('Unexpected error: %s', str(e))
        return {
            'statusCode': HTTPStatus.INTERNAL_SERVER_ERROR,
            'body': 'Internal server error'
        }
