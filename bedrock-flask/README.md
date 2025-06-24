# Bedrock Agent with Auth0 Integration

A Flask-based web application that integrates AWS Bedrock Agent with Auth0 authentication and Okta federated identity management. This application provides a secure chat interface where users can interact with a Bedrock agent while maintaining proper authentication and authorization.

## Features

- 🔐 **Auth0 Authentication**: Secure user authentication using Auth0
- 🔗 **Okta Federation**: Federated identity management with Okta
- 🤖 **AWS Bedrock Agent**: AI-powered chat interface using AWS Bedrock
- 🔒 **Token Vault**: Automatic token refresh and federated token exchange
- 🛡️ **Session Management**: Secure session handling with CSRF protection

## Prerequisites

- Python 3.8 or higher
- AWS Account with Bedrock access
- Auth0 Account
- Okta Account (for federated authentication)
- AWS CLI configured (optional, for local development)

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd bedrock-agent-app
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   Create a `.env` file in the root directory:
   ```env
   # Flask Configuration
   APP_SECRET_KEY=your-random-secret-key
   
   # Auth0 Configuration
   AUTH0_CLIENT_ID=your-auth0-client-id
   AUTH0_CLIENT_SECRET=your-auth0-client-secret
   AUTH0_DOMAIN=your-auth0-domain.auth0.com
   AUTH0_CALLBACK_URL=http://127.0.0.1:5000/callback
   
   # AWS Configuration
   AWS_DEFAULT_REGION=us-east-1
   AWS_ACCESS_KEY_ID=your-aws-access-key
   AWS_SECRET_ACCESS_KEY=your-aws-secret-key
   
   # Bedrock Configuration
   BEDROCK_AGENT_ID=your-bedrock-agent-id
   BEDROCK_AGENT_ALIAS_ID=your-bedrock-agent-alias-id
   BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
   ```

## Configuration

### Auth0 Setup

1. Create an Auth0 application
2. Configure the following settings:
   - **Application Type**: Regular Web Application
   - **Allowed Callback URLs**: `http://127.0.0.1:5000/callback`
   - **Allowed Logout URLs**: `http://127.0.0.1:5000`
   - **Scopes**: `openid profile email offline_access okta.users.read`

3. Set up Okta as a federated connection in Auth0

### AWS Bedrock Setup

1. Create a Bedrock Agent in AWS Console
2. Configure the agent with appropriate action groups
3. Note down the Agent ID and Agent Alias ID

### Okta Configuration

1. Set up Okta as an OIDC provider
2. Configure the connection in Auth0
3. Ensure proper scopes are configured for user management

## Usage

### Running the Application

1. **Start the Flask application**
   ```bash
   python app/agent.py
   ```

2. **Access the application**
   - Open your browser and navigate to `http://127.0.0.1:5000`
   - You will be redirected to Auth0 for authentication
   - After successful authentication, you'll be redirected back to the application

3. **Using the Chat Interface**
   - Once authenticated, you can interact with the Bedrock agent
   - Send messages through the chat interface
   - The agent will process your requests and provide responses

### API Endpoints

- `GET /` - Main application page (requires authentication)
- `GET /login` - Initiate Auth0 login flow
- `GET /callback` - Handle Auth0 callback
- `GET /logout` - Handle user logout
- `POST /chat` - Chat endpoint for Bedrock agent interaction
