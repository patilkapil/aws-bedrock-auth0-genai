"""
AWS Lambda function for CIBA (Client Initiated Backchannel Authentication) implementation.

This module provides a Lambda handler that implements the CIBA authentication flow
using Auth0 as the identity provider. It supports polling-based token retrieval
and integrates with AWS Bedrock agents for secure user authentication.

Key Features:
- CIBA authentication flow implementation
- Token polling with exponential backoff
- Integration with AWS Bedrock agents
- Comprehensive error handling and logging
- Configurable authentication parameters

Author: [Your Name]
Date: [Current Date]
Version: 1.0.0
"""

import logging
import json
import time
from typing import Dict, Any, Optional
from http import HTTPStatus
import requests

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configuration constants - Replace with environment variables in production
AUTH0_DOMAIN = "YOUR_AUTH0_DOMAIN"  # e.g., "your-tenant.us.auth0.com"
AUTH0_CLIENT_ID = "YOUR_CLIENT_ID"
AUTH0_CLIENT_SECRET = "YOUR_CLIENT_SECRET"

# CIBA configuration
DEFAULT_SCOPE = "openid profile"
DEFAULT_BINDING_MESSAGE = "123456"
DEFAULT_POLLING_INTERVAL = 5
DEFAULT_TIMEOUT_BUFFER = 10  # seconds


def poll_for_token(token_url: str, auth_req_id: str, expires_in: int, interval: int) -> Optional[Dict[str, Any]]:
    """
    Poll for authentication token using CIBA flow.
    
    This function implements the polling mechanism as specified in the CIBA specification.
    It handles various error conditions including authorization_pending and slow_down
    responses from the authorization server.
    
    Args:
        token_url (str): The token endpoint URL
        auth_req_id (str): The authentication request ID from the initial CIBA request
        expires_in (int): Maximum time in seconds to wait for authentication
        interval (int): Initial polling interval in seconds
        
    Returns:
        Optional[Dict[str, Any]]: Token response if successful, None otherwise
        
    Raises:
        requests.RequestException: If network requests fail
    """
    start_time = time.time()
    current_interval = interval
    
    logger.info(f"Starting token polling for auth_req_id: {auth_req_id}")
    logger.info(f"Token expires in: {expires_in} seconds, initial interval: {interval} seconds")

    while True:
        # Check if we've exceeded the timeout
        elapsed_time = time.time() - start_time
        if elapsed_time > (expires_in - DEFAULT_TIMEOUT_BUFFER):
            logger.warning(f"Authentication request timed out after {elapsed_time:.2f} seconds")
            return None

        # Prepare token request payload
        token_payload = {
            'grant_type': 'urn:openid:params:grant-type:ciba',
            'auth_req_id': auth_req_id,
            'client_id': AUTH0_CLIENT_ID,
            'client_secret': AUTH0_CLIENT_SECRET
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }

        try:
            logger.debug(f"Polling token endpoint (attempt {int(elapsed_time / current_interval) + 1})")
            token_response = requests.post(token_url, data=token_payload, headers=headers)

            if token_response.status_code == 200:
                logger.info("Token successfully retrieved")
                return token_response.json()

            # Handle error responses
            error_response = token_response.json()
            error = error_response.get('error')
            error_description = error_response.get('error_description', '')

            if error == 'authorization_pending':
                logger.debug(f"Authorization pending: {error_description}")
                time.sleep(current_interval)
                continue

            if error == 'slow_down':
                logger.info(f"Server requested slow down: {error_description}")
                current_interval += 5
                time.sleep(current_interval)
                continue

            # Handle other errors
            logger.error(f"Authentication failed with error: {error} - {error_description}")
            return None

        except requests.RequestException as e:
            logger.error(f"Network error during token polling: {str(e)}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON response from token endpoint: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during token polling: {str(e)}")
            return None


def initiate_ciba_authentication(user_id: str, scope: str = DEFAULT_SCOPE, 
                                binding_message: str = DEFAULT_BINDING_MESSAGE) -> Optional[Dict[str, Any]]:
    """
    Initiate CIBA authentication flow.
    
    This function creates the initial CIBA authentication request using the
    backchannel authorization endpoint. It constructs the login_hint using
    the issuer-subject format as required by Auth0.
    
    Args:
        user_id (str): The user identifier for authentication
        scope (str): OAuth2 scope for the authentication request
        binding_message (str): Optional binding message for user verification
        
    Returns:
        Optional[Dict[str, Any]]: Authentication response if successful, None otherwise
        
    Raises:
        requests.RequestException: If the authentication request fails
    """
    url = f"https://{AUTH0_DOMAIN}/bc-authorize"
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # Construct login_hint in issuer-subject format as required by Auth0
    login_hint = {
        "format": "iss_sub",
        "iss": f"https://{AUTH0_DOMAIN}/",
        "sub": user_id
    }

    payload = {
        "client_id": AUTH0_CLIENT_ID,
        "client_secret": AUTH0_CLIENT_SECRET,
        "login_hint": json.dumps(login_hint),
        "scope": scope,
        "binding_message": binding_message
    }

    logger.info(f"Initiating CIBA authentication for user: {user_id}")
    logger.debug(f"Authentication endpoint: {url}")
    logger.debug(f"Scope: {scope}, Binding message: {binding_message}")

    try:
        response = requests.post(url, headers=headers, data=payload)
        auth_data = response.json()

        if response.status_code != 200:
            logger.error(f"Failed to initiate authentication: {response.status_code}")
            logger.error(f"Response: {auth_data}")
            return None

        logger.info("CIBA authentication initiated successfully")
        logger.debug(f"Auth response: {auth_data}")
        return auth_data

    except requests.RequestException as e:
        logger.error(f"Network error during authentication initiation: {str(e)}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON response from auth endpoint: {str(e)}")
        return None


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler for processing Bedrock agent requests with CIBA authentication.
    
    This handler integrates with AWS Bedrock agents to provide secure user authentication
    using the CIBA flow. It extracts user information from session attributes,
    initiates authentication, and polls for completion.
    
    The function follows this flow:
    1. Extract user information from session attributes
    2. Initiate CIBA authentication request
    3. Poll for token completion
    4. Return appropriate response to the Bedrock agent
    
    Args:
        event (Dict[str, Any]): Lambda event containing action details and session attributes
        context (Any): Lambda context object
        
    Returns:
        Dict[str, Any]: Response containing the action execution results
        
    Raises:
        KeyError: If required fields are missing from the event
    """
    logger.info("Lambda handler invoked")
    logger.debug(f"Event received: {json.dumps(event, default=str)}")

    try:
        # Extract session attributes and user information
        session_attributes = event.get("sessionAttributes", {})
        user_id = session_attributes.get('user_id')
        
        if not user_id:
            logger.error("User ID not found in session attributes")
            return {
                'statusCode': HTTPStatus.BAD_REQUEST,
                'body': 'Error: User ID not found in session attributes'
            }

        logger.info(f"Processing CIBA request for user: {user_id}")

        # Extract Bedrock agent parameters
        action_group = event['actionGroup']
        function = event['function']
        message_version = event.get('messageVersion', 1)
        
        # Step 1: Initiate CIBA authentication
        auth_data = initiate_ciba_authentication(user_id)
        if not auth_data:
            logger.error("Failed to initiate CIBA authentication")
            response_body = {
                'TEXT': {
                    'body': 'Failed to initiate user authentication process'
                }
            }
        else:
            # Extract authentication parameters
            auth_req_id = auth_data.get('auth_req_id')
            expires_in = auth_data.get('expires_in')
            interval = auth_data.get('interval', DEFAULT_POLLING_INTERVAL)

            logger.info(f"Authentication request ID: {auth_req_id}")
            logger.info(f"Expires in: {expires_in} seconds, polling interval: {interval} seconds")

            # Step 2: Poll for token completion
            token_url = f'https://{AUTH0_DOMAIN}/oauth/token'
            logger.info("Waiting for user authentication completion...")
            
            tokens = poll_for_token(token_url, auth_req_id, expires_in, interval)
            
            # Step 3: Handle authentication result
            if tokens:
                logger.info("User authentication completed successfully")
                response_body = {
                    'TEXT': {
                        'body': 'User identity has been successfully validated and authentication completed'
                    }
                }
            else:
                logger.warning("User authentication failed or timed out")
                response_body = {
                    'TEXT': {
                        'body': 'User identity validation was unsuccessful. Please try again.'
                    }
                }

        # Construct Bedrock agent response
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

        logger.info("Lambda handler completed successfully")
        logger.debug(f"Response: {json.dumps(response, default=str)}")
        return response

    except KeyError as e:
        logger.error(f'Missing required field: {str(e)}')
        return {
            'statusCode': HTTPStatus.BAD_REQUEST,
            'body': f'Error: Missing required field - {str(e)}'
        }
    except Exception as e:
        logger.error(f'Unexpected error in lambda handler: {str(e)}')
        return {
            'statusCode': HTTPStatus.INTERNAL_SERVER_ERROR,
            'body': 'Internal server error occurred during authentication processing'
        }
