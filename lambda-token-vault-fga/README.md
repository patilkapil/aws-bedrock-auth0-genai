# Lambda Token Vault FGA

AWS Lambda function for processing Bedrock agent requests with Fine-Grained Authorization (FGA) and DynamoDB session storage. This function retrieves user session data from DynamoDB, checks FGA permissions, and integrates with Okta to retrieve user group information.

## Features

- **DynamoDB Session Storage**: Retrieves federated tokens from secure DynamoDB session storage
- **FGA Authorization**: Fine-grained authorization checks before API calls
- **Okta Integration**: Retrieves user groups from Okta using federated tokens
- **Production Ready**: Environment-based configuration with comprehensive error handling
- **Secure Token Handling**: No tokens passed through Bedrock agent sessions

## Architecture

```
Bedrock Agent -> Lambda Function -> DynamoDB (Session Data)
                                 -> FGA Authorizer Lambda
                                 -> Okta API
```

## Environment Variables

### Required Configuration

```bash
# DynamoDB Configuration
SESSION_TABLE_NAME=bedrock-sessions

# FGA Configuration
FGA_AUTHORIZER_FUNCTION_NAME=fga_authorizer-bedrock-aws-okta
DEFAULT_OBJECT=okta:groups
DEFAULT_RELATION=read_okta

# Okta Configuration
OKTA_DOMAIN=https://your-okta-domain.oktapreview.com

# Auth0 Configuration (for legacy token exchange if needed)
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your_client_id
AUTH0_CLIENT_SECRET=your_client_secret
AUTH0_CONNECTION=your_connection_name
AUTH0_SCOPE=okta.users.read okta.users.read.self
```

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Create DynamoDB Table

Ensure the DynamoDB table exists with:
- **Table Name**: `bedrock-sessions` (or value from `SESSION_TABLE_NAME`)
- **Partition Key**: `session_id` (String)
- **TTL Attribute**: `ttl` (Number)

### 3. Deploy Lambda Function

1. Package the Lambda function
2. Set the required environment variables
3. Ensure Lambda execution role has permissions for:
   - DynamoDB read access to session table
   - Lambda invoke permissions for FGA authorizer
   - CloudWatch Logs

### 4. Configure Bedrock Agent

Configure your Bedrock agent to call this Lambda function with session attributes containing:
- `session_id`: Session identifier for DynamoDB lookup
- `logged_in_user`: User identifier for FGA authorization

## Function Flow

### 1. Session Validation
- Extracts `session_id` from Bedrock agent session attributes
- Retrieves session data from DynamoDB
- Validates session exists and contains federated token

### 2. FGA Authorization
- Calls FGA authorizer Lambda function
- Checks if user has permission for specified object/relation
- Returns authorization error if not permitted

### 3. Okta API Integration
- Uses federated token from session data
- Calls Okta API to retrieve user groups
- Returns formatted group list

## Input/Output

### Input (Bedrock Agent Event)
```json
{
  "actionGroup": "user-management",
  "function": "get-user-groups",
  "messageVersion": 1,
  "parameters": [
    {
      "name": "user",
      "type": "string", 
      "value": "user@example.com"
    }
  ],
  "sessionAttributes": {
    "session_id": "unique-session-id",
    "logged_in_user": "current-user@example.com"
  }
}
```

### Output (Bedrock Agent Response)
```json
{
  "response": {
    "actionGroup": "user-management",
    "function": "get-user-groups",
    "functionResponse": {
      "responseBody": {
        "TEXT": {
          "body": "Group1,Group2,Group3",
          "contentType": "text/plain"
        }
      }
    }
  },
  "messageVersion": 1
}
```

## Error Handling

The function handles various error scenarios:

- **Session Not Found**: Returns error if session_id not in DynamoDB
- **Missing Token**: Returns error if federated token not available
- **FGA Authorization Failure**: Returns unauthorized message
- **Okta API Errors**: Returns specific error messages for API failures
- **Invalid Parameters**: Validates required input parameters

## Security Features

- **No Token Exposure**: Tokens stored securely in DynamoDB, not in Bedrock sessions
- **FGA Authorization**: Permission checks before accessing external APIs
- **Session Validation**: Validates session existence and validity
- **Comprehensive Logging**: Detailed logging for debugging and monitoring

## DynamoDB Schema

Expected session data structure:
```json
{
  "session_id": "unique-uuid",
  "federated_token": "okta-api-token", 
  "user_id": "auth0-user-id",
  "user_email": "user@example.com",
  "refresh_token": "auth0-refresh-token",
  "ttl": 1234567890,
  "created_at": 1234567890
}
```

## AWS Permissions

Lambda execution role needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem"
      ],
      "Resource": "arn:aws:dynamodb:region:account:table/bedrock-sessions"
    },
    {
      "Effect": "Allow", 
      "Action": [
        "lambda:InvokeFunction"
      ],
      "Resource": "arn:aws:lambda:region:account:function:fga_authorizer-bedrock-aws-okta"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream", 
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

## Production Deployment

1. Set all environment variables securely
2. Configure proper IAM roles and permissions
3. Set up monitoring and alerting
4. Test with sample Bedrock agent requests
5. Monitor DynamoDB and Okta API usage

## Legacy Support

The function includes a legacy `get_tokenset()` function for backwards compatibility with direct token exchange flows, though the primary flow now uses DynamoDB session storage.

## License

MIT
 