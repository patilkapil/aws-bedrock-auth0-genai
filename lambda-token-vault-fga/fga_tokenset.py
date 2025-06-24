import boto3
import logging
from typing import Dict, Any
from http import HTTPStatus
import requests
import json
import os

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_tokenset(refresh_token: str) -> str:
    """
    Exchange a refresh token for an access token using Auth0's token exchange endpoint.
    
    This function implements the OAuth 2.0 token exchange flow to get a federated
    connection access token that can be used to access external APIs (like Okta).
    
    Args:
        refresh_token (str): The refresh token to exchange
        
    Returns:
        str: The access token if successful, None otherwise
        
    Note:
        This function requires the following environment variables to be set:
        - AUTH0_DOMAIN: Your Auth0 domain
        - AUTH0_CLIENT_ID: Your Auth0 client ID
        - AUTH0_CLIENT_SECRET: Your Auth0 client secret
        - AUTH0_CONNECTION: The name of your federated connection
    """
    # Get configuration from environment variables
    auth0_domain = os.environ.get('AUTH0_DOMAIN')
    client_id = os.environ.get('AUTH0_CLIENT_ID')
    client_secret = os.environ.get('AUTH0_CLIENT_SECRET')
    connection = os.environ.get('AUTH0_CONNECTION')
    
    if not all([auth0_domain, client_id, client_secret, connection]):
        logger.error("Missing required Auth0 environment variables")
        return None

    url = f"https://{auth0_domain}/oauth/token"
    headers = {"content-type": "application/json"}
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
        "subject_token": refresh_token,
        "connection": connection,
        "audience": f"https://{auth0_domain}/api/v2/",
        "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
        "scope": "okta.users.read okta.users.read.self"
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        tokenset = response.json()
        logger.info("Successfully obtained access token")
        return tokenset.get("access_token")
    except requests.exceptions.RequestException as e:
        error_text = e.response.text if hasattr(e, 'response') else "No response"
        logger.error("Error getting token: %s", error_text)
        return None


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler for processing Bedrock agent requests with FGA authorization.
    
    This Lambda function demonstrates how to:
    1. Extract user information from Bedrock agent session attributes
    2. Use Fine-Grained Authorization (FGA) to check permissions
    3. Integrate with Okta to retrieve user group information
    4. Return structured responses for Bedrock agents
    
    Args:
        event (Dict[str, Any]): The Lambda event containing action details
        context (Any): The Lambda context object

    Returns:
        Dict[str, Any]: Response containing the action execution results

    Raises:
        KeyError: If required fields are missing from the event
    """
    try:
        logger.info("Processing Bedrock agent request: %s", event)
        
        # Extract required fields from the event
        action_group = event['actionGroup']
        function = event['function']
        message_version = event.get('messageVersion', 1)
        parameters = event.get('parameters', [])
        session_attributes = event.get("sessionAttributes", {})
        
        # Get federated token from session attributes
        federated_token = session_attributes.get('federated_token')
        if not federated_token:
            logger.error("No federated token found in session attributes")
            return _create_error_response("No federated token available", action_group, function, message_version)
        
        logger.info("Federated token retrieved successfully")
        logger.info("User parameter: %s", parameters[0]['value'] if parameters else "No parameters")
        
        actiongroup_output = ""

        # Prepare FGA authorization request
        invoke_fga_authz = {
            "user": session_attributes['logged_in_user'],
            "object": "okta:groups",
            "relation": "read_okta"
        }        

        # Call FGA authorizer Lambda function
        lambda_client = boto3.client('lambda')
        fga_response = lambda_client.invoke(
            FunctionName=os.environ.get('FGA_AUTHORIZER_FUNCTION_NAME', 'fga_authorizer-bedrock-aws-okta'),
            InvocationType='RequestResponse',
            Payload=json.dumps(invoke_fga_authz)
        )

        # Parse FGA response
        response_payload = fga_response['Payload'].read()
        decoded_response = json.loads(response_payload)
        logger.info("FGA authorization result: %s", decoded_response)
        
        if decoded_response.get('isAuthorized') == True:
            # User is authorized, proceed with Okta group retrieval
            if parameters and parameters[0]['value'] != "user":
                actiongroup_output = _get_okta_user_groups(parameters[0]['value'], federated_token)
            else:
                actiongroup_output = "No valid user parameter provided"
        else:
            actiongroup_output = "You are not authorized to perform this action"
            
        # Create response for Bedrock agent
        response_body = {
            'TEXT': {
                'body': actiongroup_output,
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
        
        response = {
            'response': action_response,
            'messageVersion': message_version
        }

        logger.info('Response: %s', response)
        return response

    except KeyError as e:
        logger.error('Missing required field: %s', str(e))
        return {
            'statusCode': HTTPStatus.BAD_REQUEST,
            'body': f'Error: {str(e)}'
        }
    except Exception as e:
        logger.error('Unexpected error: %s', str(e))
        return {
            'statusCode': HTTPStatus.INTERNAL_SERVER_ERROR,
            'body': 'Internal server error'
        }


def _get_okta_user_groups(email: str, api_token: str) -> str:
    """
    Retrieve user groups from Okta using the provided API token.
    
    Args:
        email (str): The user's email address
        api_token (str): The federated access token for Okta API
        
    Returns:
        str: Comma-separated list of group names or error message
    """
    try:
        okta_domain = os.environ.get('OKTA_DOMAIN', 'https://kapil.oktapreview.com')
        
        headers = {
            'Authorization': f'Bearer {api_token}',
            'Accept': 'application/json'
        }
        
        # Retrieve user by email
        user_url = f'{okta_domain}/api/v1/users/{email}'
        user_response = requests.get(user_url, headers=headers)
        
        if user_response.status_code != 200:
            logger.error("Error retrieving user: %s - %s", user_response.status_code, user_response.text)
            return f"Error retrieving user: {user_response.status_code}"

        user = user_response.json()
        user_id = user['id']
        logger.info("User ID: %s", user_id)
        
        # Retrieve user's groups
        groups_url = f'{okta_domain}/api/v1/users/{user_id}/groups'
        groups_response = requests.get(groups_url, headers=headers)

        if groups_response.status_code != 200:
            logger.error("Error retrieving groups: %s - %s", groups_response.status_code, groups_response.text)
            return f"Error retrieving groups: {groups_response.status_code}"

        groups = groups_response.json()
        group_names = []
        
        logger.info("Retrieved %d groups for user", len(groups))
        for group in groups:
            group_name = group['profile']['name']
            group_names.append(group_name)
            logger.info("Group: %s", group_name)
            
        return ",".join(group_names)
        
    except Exception as e:
        logger.error("Error in _get_okta_user_groups: %s", str(e))
        return f"Error retrieving groups: {str(e)}"


def _create_error_response(error_message: str, action_group: str, function: str, message_version: int) -> Dict[str, Any]:
    """
    Create a standardized error response for Bedrock agents.
    
    Args:
        error_message (str): The error message to return
        action_group (str): The action group name
        function (str): The function name
        message_version (int): The message version
        
    Returns:
        Dict[str, Any]: Standardized error response
    """
    response_body = {
        'TEXT': {
            'body': error_message,
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
