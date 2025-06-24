# Bedrock Agent Lambda with FGA and Okta Integration

This repository contains an AWS Lambda function that demonstrates how to integrate Amazon Bedrock agents with Fine-Grained Authorization (FGA)  for secure user Okta group retrieval. The Lambda function serves as an action group for Bedrock agents, implementing proper authorization checks before accessing Okta APIs.

## Key Features

- **Fine-Grained Authorization (FGA)**: Implements authorization checks using AWS Lambda-based FGA authorizer
- **Auth0 Token Exchange**: Uses OAuth 2.0 token exchange to get federated connection access tokens
- **Okta Integration**: Retrieves user group information from Okta using federated tokens
- **Bedrock Agent Compatibility**: Returns structured responses compatible with Amazon Bedrock agents
- **Environment-based Configuration**: Uses environment variables for secure configuration management
- **Comprehensive Logging**: Implements structured logging for debugging and monitoring

## Prerequisites

- AWS Account with Lambda and Bedrock access
- Auth0 account with configured OIDC connection to Okta
- Okta account with API access
- Fine-Grained Authorization (FGA) setup (optional but recommended)

## Environment Variables

The Lambda function requires the following environment variables:

### Auth0 Configuration
```bash
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_CONNECTION=your-oidc-connection-name
```
  
### Bedrock Agent Configuration

Configure your Bedrock agent to use this Lambda function as an action group:
  
## FGA Integration

The Lambda function demonstrates FGA integration by:

1. **Authorization Request**: Sending user, object, and relation to FGA authorizer
2. **Permission Check**: Verifying if the user can read Okta groups
3. **Conditional Execution**: Only proceeding with Okta API calls if authorized

Example FGA authorization request:
```json
{
  "user": "user@example.com",
  "object": "okta:groups",
  "relation": "read_okta"
}
```

## Auth0 Token Exchange Flow

The function implements the OAuth 2.0 token exchange flow:

1. **Input**: Refresh token from session attributes
2. **Exchange**: Request federated connection access token from Auth0
3. **Output**: Access token for Okta API calls

This enables secure access to Okta APIs without storing long-lived credentials.
 