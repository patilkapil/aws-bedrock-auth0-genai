"""
AWS Lambda function for Client Initiated Backchannel Authentication (CIBA) with Auth0.

This function implements the CIBA flow allowing users to authenticate via a separate device
while processing Bedrock agent requests. The flow includes initiation, polling, and validation.
"""

import json
import logging
import os
import time
from http import HTTPStatus
from typing import Any, Dict

import requests

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables for Auth0 CIBA configuration
# These should be set in your Lambda environment for security
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "your-tenant.us.auth0.com")
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID", "your_client_id_here")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET", "your_client_secret_here")

# CIBA configuration constants
DEFAULT_SCOPE = os.getenv("CIBA_SCOPE", "openid profile")
DEFAULT_BINDING_MESSAGE = os.getenv("CIBA_BINDING_MESSAGE", "123456")


def poll_for_token(token_url: str, auth_req_id: str, expires_in: int, interval: int):
    """
    Poll for the authentication token using CIBA flow.
    
    This function continuously polls the Auth0 token endpoint until:
    - Authentication is successful (returns tokens)
    - Authentication fails or is denied
    - Request times out
    
    Args:
        token_url: Auth0 token endpoint URL
        auth_req_id: Authentication request ID from CIBA initiation
        expires_in: Maximum time to wait for authentication (seconds)
        interval: Polling interval between requests (seconds)
        
    Returns:
        Token response dictionary if successful, None otherwise
    """
    start_time = time.time()

    while True:
        # Check if polling has exceeded the allowed time
        if time.time() - start_time > expires_in:
            logger.warning("Authentication request timed out after %d seconds", expires_in)
            return None

        # Prepare token request payload for CIBA grant type
        token_payload = {
            'grant_type': 'urn:openid:params:grant-type:ciba',  # CIBA-specific grant type
            'auth_req_id': auth_req_id,                         # Request ID from initiation
            'client_id': AUTH0_CLIENT_ID,
            'client_secret': AUTH0_CLIENT_SECRET
        }

        # Set headers for form-encoded request
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            # Make token request to Auth0
            token_response = requests.post(token_url, data=token_payload, headers=headers)

            # Check if authentication was successful
            if token_response.status_code == 200:
                logger.info("CIBA authentication successful")
                return token_response.json()

            # Parse error response for specific handling
            error_response = token_response.json()
            error = error_response.get('error')

            # Handle authorization still pending (continue polling)
            if error == 'authorization_pending':
                logger.info('Authorization pending. Retrying in %d seconds...', interval)
                time.sleep(interval)
                continue

            # Handle rate limiting (slow down polling)
            if error == 'slow_down':
                logger.info('Rate limited. Increasing polling interval by 5 seconds.')
                interval += 5  # Increase interval to avoid rate limiting
                time.sleep(interval)
                continue

            # Handle other authentication errors (stop polling)
            logger.error('Authentication failed with error: %s', error)
            return None

        except Exception as e:
            logger.error('Error during token polling: %s', str(e))
            return None


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler for processing Bedrock agent CIBA authentication requests.
    
    Flow:
    1. Extract user ID from Bedrock session attributes
    2. Initiate CIBA authentication request with Auth0
    3. Poll for authentication completion
    4. Return success/failure response to Bedrock agent

    Args:
        event: The Lambda event containing action details and session attributes
        context: The Lambda context object

    Returns:
        Response containing the CIBA authentication results

    Raises:
        KeyError: If required fields are missing from the event
    """
    # Extract session attributes from Bedrock agent event
    # These contain user information passed from the main application
    session_attributes = event.get("sessionAttributes", {})

    # Log the incoming event and user information
    logger.info('Processing CIBA authentication request')
    logger.info('Event received: %s', event)
    logger.info('CIBA request initiated for user: %s', session_attributes.get('user_id'))

    # Extract user ID for CIBA authentication
    # This identifies the user who needs to authenticate via the secondary device
    user_id = session_attributes['user_id']
    
    # CIBA request configuration
    scope = DEFAULT_SCOPE                    # OAuth scopes to request
    binding_message = DEFAULT_BINDING_MESSAGE  # Optional verification code for user

    try:
        # Extract required fields from Bedrock agent event
        action_group = event['actionGroup']
        function = event['function']
        message_version = event.get('messageVersion', 1)
        parameters = event.get('parameters', [])
        
        # Construct Auth0 CIBA endpoints
        ciba_url = f"https://{AUTH0_DOMAIN}/bc-authorize"      # CIBA initiation endpoint
        token_url = f'https://{AUTH0_DOMAIN}/oauth/token'      # Token polling endpoint

        # Set headers for CIBA initiation request
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        # Construct login_hint in required Auth0 format
        # This tells Auth0 which user should authenticate
        login_hint = {
            "format": "iss_sub",                           # Format specification
            "iss": f"https://{AUTH0_DOMAIN}/",            # Issuer (Auth0 domain)
            "sub": user_id                                # Subject (user identifier)
        }

        # Prepare CIBA initiation payload
        payload = {
            "client_id": AUTH0_CLIENT_ID,
            "client_secret": AUTH0_CLIENT_SECRET,
            "login_hint": json.dumps(login_hint),  # JSON-encoded login hint
            "scope": scope,                        # Requested OAuth scopes
            "binding_message": binding_message     # Optional verification code
        }

        # Step 1: Initiate CIBA authentication request
        logger.info("Initiating CIBA authentication for user: %s", user_id)
        response = requests.post(ciba_url, headers=headers, data=payload)
        auth_data = response.json()

        # Check if CIBA initiation was successful
        if response.status_code != 200:
            logger.error("Failed to initiate CIBA authentication: %d", response.status_code)
            logger.error("Auth0 response: %s", auth_data)
            # Note: Using exit(1) as in original structure
            exit(1)

        # Extract authentication request details from Auth0 response
        auth_req_id = auth_data.get('auth_req_id')    # Unique request identifier
        expires_in = auth_data.get('expires_in')      # Maximum wait time
        interval = auth_data.get('interval', 5)       # Polling interval

        # Log CIBA initiation success
        logger.info('CIBA authentication request initiated successfully')
        logger.info('Authentication request ID: %s', auth_req_id)
        logger.info('Expires in: %d seconds', expires_in)
        logger.info('Polling interval: %d seconds', interval)

        # Step 2: Poll for authentication completion
        logger.info("Waiting for user authentication on secondary device...")
        tokens = poll_for_token(token_url, auth_req_id, expires_in, interval)
        
        # Step 3: Prepare response based on authentication result
        response_body = ""
        if tokens:
            # Authentication successful - user completed CIBA flow
            logger.info("CIBA authentication completed successfully")
            response_body = {
                'TEXT': {
                    'body': 'The Identity for the user executing the command has been validated and password instructions have been shared'
                }
            }
        else:
            # Authentication failed or timed out
            logger.warning("CIBA authentication failed or timed out")
            response_body = {
                'TEXT': {
                    'body': 'The Identity can not be validated successfully'
                }
            }

        # Prepare Bedrock agent response in required format
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

        logger.info('CIBA process completed. Response: %s', response)
        return response

    except KeyError as e:
        # Handle missing required fields in the event
        logger.error('Missing required field in event: %s', str(e))
        return {
            'statusCode': HTTPStatus.BAD_REQUEST,
            'body': f'Error: {str(e)}'
        }
    except Exception as e:
        # Handle any unexpected errors during CIBA process
        logger.error('Unexpected error during CIBA authentication: %s', str(e))
        return {
            'statusCode': HTTPStatus.INTERNAL_SERVER_ERROR,
            'body': 'Internal server error'
        }
