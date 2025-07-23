# Step 01. Install the SDK
# Install the SDK by following the steps at https://docs.fga.dev/integration/install-sdk
# pip3 install openfga_sdk
import asyncio

import openfga_sdk
from openfga_sdk.client import OpenFgaClient,ClientConfiguration
from openfga_sdk.client.models import ClientCheckRequest
from openfga_sdk.credentials import Credentials, CredentialConfiguration

def get_env_variable(var_name, default=None, required=True):
    """
    Helper to fetch environment variables and optionally enforce their presence.
    """
    value = os.getenv(var_name, default)
    if required and value is None:
        raise EnvironmentError(f"Missing required environment variable: {var_name}")
    return value

def build_fga_client():
    """
    Build and return an OpenFgaClient using environment variables for configuration.
    """
    credentials = Credentials(
        method='client_credentials',
        configuration=CredentialConfiguration(
            api_issuer=get_env_variable('FGA_API_ISSUER'),
            api_audience=get_env_variable('FGA_API_AUDIENCE'),
            client_id=get_env_variable('FGA_CLIENT_ID'),
            client_secret=get_env_variable('FGA_CLIENT_SECRET')
        )
    )
    configuration = ClientConfiguration(
        api_scheme=get_env_variable('FGA_API_SCHEME', 'https', required=False),
        api_host=get_env_variable('FGA_API_HOST'),
        store_id=get_env_variable('FGA_STORE_ID'),
        authorization_model_id=get_env_variable('FGA_AUTHORIZATION_MODEL_ID', required=False),
        credentials=credentials,
    )
    return OpenFgaClient(configuration)

async def check_access(user_obj):
    """
    Asynchronously check access for a user-object-relation tuple using OpenFGA.
    """
    async with build_fga_client() as fga_client:
        options = {}
        model_id = os.getenv('FGA_AUTHORIZATION_MODEL_ID')
        if model_id:
            options['authorization_model_id'] = model_id
        body = ClientCheckRequest(
            user=f"user:{user_obj['user']}",
            relation=user_obj['relation'],
            object=user_obj['object'],
        )
        response = await fga_client.check(body, options)
        await fga_client.close()
        return response

def lambda_handler(event, context):
    """
    AWS Lambda handler for FGA authorization check.
    Expects event to contain 'user', 'relation', and 'object'.
    Returns whether the user is authorized for the relation on the object.
    """
    # Validate input
    for key in ('user', 'relation', 'object'):
        if key not in event:
            return {
                'statusCode': 400,
                'body': f"Missing required field: {key}"
            }
    user_obj = {
        'user': event['user'],
        'relation': event['relation'],
        'object': event['object']
    }
    # Run the async check
    result = asyncio.run(check_access(user_obj))
    response = {
        "isAuthorized": result.allowed,
    }
    return {
        "statusCode": 200,
        "isAuthorized": result.allowed,
        "body": response
    }
