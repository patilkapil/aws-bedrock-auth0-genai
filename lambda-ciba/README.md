# CIBA Authentication Lambda Function

This project implements a Client Initiated Backchannel Authentication (CIBA) flow using AWS Lambda and Auth0 as the identity provider. The function integrates with AWS Bedrock agents to provide secure user authentication without requiring direct user interaction during the authentication process.
 


## Prerequisites

- AWS Account with Lambda and Bedrock access
- Auth0 account with CIBA enabled
- Python 3.8+ runtime
- Required Python packages (see `requirements.txt`)

## Setup Instructions

### 1. Auth0 Configuration

1. Create an Auth0 application with CIBA enabled
2. Configure the following settings in Auth0:
   - **Application Type**: Machine to Machine
   - **Token Endpoint Authentication Method**: Client Secret Post
   - **Grant Types**: Enable "Client Initiated Backchannel Authentication"

3. Note down your Auth0 configuration:
   - Domain
   - Client ID
   - Client Secret

### 2. Environment Variables

Replace the placeholder values in the code with your actual Auth0 credentials:

```python
AUTH0_DOMAIN = "your-tenant.us.auth0.com"
AUTH0_CLIENT_ID = "your-client-id"
AUTH0_CLIENT_SECRET = "your-client-secret"
```

**⚠️ Security Note**: In production, use AWS Lambda environment variables or AWS Secrets Manager to store sensitive credentials.

### 3. AWS Lambda Deployment

1. Create a new Lambda function
2. Set the runtime to Python 3.8 or higher
3. Upload the `dummy_lambda.py` file
4. Configure the function timeout (recommended: 5 minutes)
5. Set up appropriate IAM roles and permissions

### 4. AWS Bedrock Agent Configuration

1. Create a Bedrock agent
2. Add this Lambda function as an action
3. Configure the action schema to include:
   - `user_id` in session attributes
   - Appropriate response format

## Usage

### Function Flow

1. **Event Reception**: Lambda receives event from Bedrock agent
2. **User Extraction**: Extracts user ID from session attributes
3. **CIBA Initiation**: Creates authentication request with Auth0
4. **Token Polling**: Polls for authentication completion
5. **Response**: Returns authentication result to Bedrock agent