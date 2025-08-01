"""
AWS Lambda function for Fine-Grained Authorization (FGA) checks using OpenFGA SDK.
"""

import asyncio
import os

import openfga_sdk
from openfga_sdk.client import OpenFgaClient, ClientConfiguration
from openfga_sdk.client.models import ClientCheckRequest
from openfga_sdk.credentials import Credentials, CredentialConfiguration

# Environment variables for FGA configuration
# These should be set in your Lambda environment for security
FGA_API_ISSUER = os.getenv("FGA_API_ISSUER", "fga.us.auth0.com")
FGA_API_AUDIENCE = os.getenv("FGA_API_AUDIENCE", "https://api.us1.fga.dev/")
FGA_CLIENT_ID = os.getenv("FGA_CLIENT_ID", "your_client_id_here")
FGA_CLIENT_SECRET = os.getenv("FGA_CLIENT_SECRET", "your_client_secret_here")
FGA_API_SCHEME = os.getenv("FGA_API_SCHEME", "https")
FGA_API_HOST = os.getenv("FGA_API_HOST", "api.us1.fga.dev")
FGA_STORE_ID = os.getenv("FGA_STORE_ID", "your_store_id_here")
FGA_AUTHORIZATION_MODEL_ID = os.getenv("FGA_AUTHORIZATION_MODEL_ID", "your_model_id_here")


async def main(user_obj):
    """
    Perform FGA authorization check for the given user object.
    
    Args:
        user_obj: Dictionary containing user, relation, and object for authorization check
        
    Returns:
        FGA check response object
    """
    # Step 1: Set up client credentials for Auth0 authentication
    # This uses the client_credentials flow to authenticate with the FGA service
    credentials = Credentials(
        method='client_credentials',
        configuration=CredentialConfiguration(
            api_issuer=FGA_API_ISSUER,
            api_audience=FGA_API_AUDIENCE,
            client_id=FGA_CLIENT_ID,
            client_secret=FGA_CLIENT_SECRET
        )
    )
    
    # Step 2: Configure the OpenFGA client with connection details
    # This includes the store ID and authorization model for the specific tenant
    configuration = ClientConfiguration(
        api_scheme=FGA_API_SCHEME,
        api_host=FGA_API_HOST,
        store_id=FGA_STORE_ID,
        authorization_model_id=FGA_AUTHORIZATION_MODEL_ID,
        credentials=credentials,
    )
    
    # Step 3: Perform the authorization check
    async with OpenFgaClient(configuration) as fga_client:
        # Optional: Specify authorization model ID for better performance
        options = {"authorization_model_id": FGA_AUTHORIZATION_MODEL_ID}
        
        # Create the check request with user:prefix format
        # Format: user:<user_id> can <relation> <object>
        body = ClientCheckRequest(
            user='user:' + user_obj['user'],  # e.g., "user:alice@example.com"
            relation=user_obj['relation'],    # e.g., "read"
            object=user_obj['object'],        # e.g., "document:123"
        )
        
        # Execute the authorization check
        response = await fga_client.check(body, options)
        return response
        await fga_client.close()  # Cleanup connection


def lambda_handler(event, context):
    """
    AWS Lambda handler for FGA authorization checks.
    
    Args:
        event: Lambda event containing user, relation, and object
        context: Lambda context object
        
    Returns:
        Authorization response with statusCode and isAuthorized flag
    """
    # Log the incoming event for debugging
    print(event)
    
    # Extract authorization parameters from the event
    # Expected format: {"user": "alice@example.com", "relation": "read", "object": "document:123"}
    user_obj = {}
    user_obj['relation'] = event['relation']  # The permission being checked
    user_obj['user'] = event['user']         # The user requesting access
    user_obj['object'] = event['object']     # The resource being accessed
    
    # Log the parsed user object
    print(user_obj)
    
    # Execute the async FGA check using asyncio
    # This will return the authorization result from OpenFGA
    result = asyncio.run(main(user_obj))
    
    # Build the response object for the caller
    response = {
        "isAuthorized": result.allowed,  # Boolean: true if authorized, false if not
    }
    
    # Log the final response
    print(response)

    # Return the Lambda response in the expected format
    # Both statusCode and isAuthorized are included for flexibility
    return {
        "statusCode": 200,                    # HTTP status code
        "isAuthorized": result.allowed,       # Authorization result
    }
