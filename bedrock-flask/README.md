# Bedrock Flask Agent

A Flask web application that integrates Auth0 authentication with AWS Bedrock agents, featuring secure session management and token vault functionality.

## Features

- **Auth0 Authentication**: Secure user authentication with OAuth 2.0
- **Token Vault Integration**: Federated token management using Auth0 Server SDK
- **DynamoDB Session Storage**: Persistent session management with automatic TTL
- **AWS Bedrock Integration**: AI agent interactions with context preservation
- **Production Ready**: Environment-based configuration with no hardcoded secrets

## Architecture

```
User -> Auth0 Login -> Flask App -> DynamoDB (Session Storage)
                                -> AWS Bedrock Agent
                                -> Token Vault (Auth0 SDK)
```

## Environment Variables

### Required Configuration

```bash
# Application Settings
APP_SECRET_KEY=REPLACE_WITH_YOUR_SECRET_KEY
APP_BASE_URL=http://localhost:5000

# Auth0 Configuration
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CLIENT_ID=your_client_id
AUTH0_CLIENT_SECRET=your_client_secret
AUTH0_SECRET=REPLACE_WITH_YOUR_AUTH0_SECRET
AUTH0_CALLBACK_URL=http://localhost:5000/callback

# AWS Configuration
AWS_DEFAULT_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key

# Bedrock Configuration
BEDROCK_AGENT_ID=your_agent_id
BEDROCK_AGENT_ALIAS_ID=your_alias_id
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0

# DynamoDB Configuration
SESSION_TABLE_NAME=bedrock-sessions

# Connection Configuration
CONNECTION_NAME=kp-oidc
DEFAULT_SCOPE=openid profile email offline_access
OKTA_SCOPE=openid profile email offline_access okta.users.read
```

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Create DynamoDB Table

Create a DynamoDB table with the following configuration:
- **Table Name**: `bedrock-sessions` (or value from `SESSION_TABLE_NAME`)
- **Partition Key**: `session_id` (String)
- **TTL Attribute**: `ttl` (Number)

### 3. Configure Auth0

1. Create an Auth0 application
2. Set callback URL: `http://localhost:5000/callback`
3. Enable refresh tokens
4. Configure connection for token vault

### 4. Set Environment Variables

Create a `.env` file with the required configuration (see above).

### 5. Run the Application

```bash
python agent.py
```

The application will be available at `http://localhost:5000`.

## API Endpoints

### Authentication Routes

- `GET /login` - Initiate Auth0 login
- `GET /callback` - Handle Auth0 callback
- `GET /logout` - Logout user

### Application Routes

- `GET /` - Main application page (requires authentication)
- `POST /chat` - Chat with Bedrock agent (requires authentication)

### Chat API

**Request:**
```json
{
  "message": "Your message to the AI agent"
}
```

**Response:**
```json
{
  "response": "AI agent response",
  "sessionId": "unique-session-id",
  "requestId": "bedrock-request-id"
}
```

## Security Features

- **No Token Exposure**: Tokens are stored securely in DynamoDB, not sent to Bedrock
- **Session Validation**: All requests validate session existence in DynamoDB
- **Automatic Cleanup**: Sessions expire automatically using DynamoDB TTL
- **Environment Configuration**: All secrets are externalized to environment variables

## DynamoDB Schema

```json
{
  "session_id": "unique-uuid",
  "refresh_token": "auth0-refresh-token",
  "federated_token": "federated-access-token",
  "user_id": "auth0-user-id",
  "user_email": "user@example.com",
  "user_name": "User Name",
  "user_picture": "profile-picture-url",
  "ttl": 1234567890,
  "created_at": 1234567890
}
```

## Error Handling

The application includes comprehensive error handling for:
- Authentication failures
- Token retrieval errors
- DynamoDB connectivity issues
- Bedrock agent communication errors

## Production Deployment

1. Set all environment variables securely
2. Use a production WSGI server (e.g., Gunicorn)
3. Configure proper logging
4. Set up monitoring for DynamoDB and Bedrock
5. Implement proper error tracking

## License

MIT
