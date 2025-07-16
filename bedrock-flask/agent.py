import asyncio
import os
import json
import time
from functools import wraps
from traceback import print_exc

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import boto3
import requests
from os import environ as env
from auth0_server_python.auth_server import ServerClient

import uuid

from six import print_

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "your-random-secret-key")
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"

# Auth0 Configuration
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
AUTH0_BASE_URL = f"https://{AUTH0_DOMAIN}"
AUTH0_CALLBACK_URL = os.getenv("AUTH0_CALLBACK_URL", "http://127.0.0.1:5000/callback")

# AWS Configuration
AWS_DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

# Bedrock Configuration
BEDROCK_AGENT_ID = os.getenv("BEDROCK_AGENT_ID")
BEDROCK_AGENT_ALIAS_ID = os.getenv("BEDROCK_AGENT_ALIAS_ID")
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0")

# Auth0 OAuth Configuration
oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=f'{AUTH0_BASE_URL}/oauth/token',
    authorize_url=f'{AUTH0_BASE_URL}/authorize',
    client_kwargs={
        'scope': 'openid profile email offline_access okta.users.read',
    },
    server_metadata_url=f'https://{AUTH0_DOMAIN}/.well-known/openid-configuration'
)

class MemoryTransactionStore:
    """
    In-memory transaction store for Auth0 token vault operations.
    
    This class provides a simple in-memory storage mechanism for Auth0 SDK operations,
    including transaction state and token management. It implements the async interface
    required by the Auth0 ServerClient for storing and retrieving authentication state.
    
    Note: This is a development implementation. For production, consider using a
    persistent storage solution like Redis, DynamoDB, or a database.
    """
    def __init__(self):
        self.store = {}

    async def set(self, key, value, options=None):
        self.store[key] = value

    async def get(self, key, options=None):
        return self.store.get(key)

    async def delete(self, key, options=None):
        if key in self.store:
            del self.store[key]

# Initialize Auth0 Server Client for token vault
auth0_backend = ServerClient(
    domain=os.getenv("AUTH0_DOMAIN"),
    client_id=os.getenv("AUTH0_CLIENT_ID"),
    client_secret=os.getenv("AUTH0_CLIENT_SECRET"),
    secret=os.getenv("AUTH0_SECRET"),
    redirect_uri=os.getenv("APP_BASE_URL") + "/auth/callback",
    transaction_store=MemoryTransactionStore(),
    state_store=MemoryTransactionStore(),
    authorization_params={
        "scope": "openid profile email offline_access",
    }
)

def requires_auth(f):
    """
    Decorator to require authentication for protected routes.
    Redirects to login if user is not authenticated.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

# Initialize AWS Bedrock client
bedrock = boto3.client(
    service_name="bedrock-agent-runtime",
    region_name=AWS_DEFAULT_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)

@app.route("/login")
def login():
    """
    Initiate Auth0 login flow.
    Clears existing session and redirects to Auth0 for authentication.
    """
    # Clear any existing session data before starting new auth flow
    session.clear()
    return auth0.authorize_redirect(
        redirect_uri=AUTH0_CALLBACK_URL,
        response_type='code'
    )

@app.route("/callback")
def callback():
    """
    Handle Auth0 callback after successful authentication.
    Stores user information, tokens, and connection token sets in session.
    """
    try:
        # Get the token using the callback
        token = auth0.authorize_access_token()

        # Store the user info in session
        userinfo = auth0.get('userinfo').json()
        session['profile'] = {
            'user_id': userinfo['sub'],
            'name': userinfo['name'],
            'email': userinfo['email'],
            'picture': userinfo['picture']
        }

        # Create connection token sets for token vault
        connection_token_sets = [{
            "connection": "kp-oidc",
            "login_hint": userinfo.get('email'),
            "access_token": token.get("id_token"),
            "scope": "openid profile email offline_access",
        }]

        # Create comprehensive state data for token vault
        state_data = {
            "user": {
                "sub": userinfo['sub'],
                "name": userinfo.get('name'),
                "email": userinfo.get('email'),
                "picture": userinfo.get('picture'),
            },
            "id_token": token.get("id_token"),
            "refresh_token": token["refresh_token"],
            "connection_token_sets": connection_token_sets,
            "token_sets": [],
            "internal": {
                "sid": str(uuid.uuid4()),
                "created_at": int(time.time())
            }
        }
        session['auth_state_data'] = state_data

        # Store state data in Auth0 backend state store
        asyncio.run(auth0_backend.state_store.set(
            auth0_backend.state_identifier,
            state_data
        ))

        # Store the tokens in session
        session['user'] = token
        if "refresh_token" in token:
            session["refresh_token"] = token["refresh_token"]
            asyncio.run(auth0_backend.state_store.set(
                auth0_backend.state_identifier, 
                {"refresh_token": token["refresh_token"]}
            ))
            print("Stored refresh token in session and state store")
        else:
            print("No refresh token received")

        return redirect('/')
    except Exception as e:
        print(f"Error in callback: {str(e)}")
        session.clear()
        return redirect('/login')

@app.route("/logout")
def logout():
    """
    Handle user logout.
    Clears session and redirects to Auth0 logout endpoint.
    """
    session.clear()
    return redirect(
        f"{AUTH0_BASE_URL}/v2/logout?returnTo={url_for('index', _external=True)}&client_id={AUTH0_CLIENT_ID}"
    )

@app.route("/")
@requires_auth
def index():
    """
    Main application page.
    Requires authentication and displays user information.
    """
    return render_template("index.html", user=session['profile'])

def get_completion_from_response(response):
    """
    Extract completion text from Bedrock response.
    
    Args:
        response: Bedrock agent response object
        
    Returns:
        str: Combined completion text
    """
    completion = ""
    for event in response.get("completion"):
        chunk = event["chunk"]
        completion += chunk["bytes"].decode()
    return completion

async def get_token_from_token_vault():
    """
    Get access token from token vault using Auth0 SDK.
    
    Returns:
        str: Access token for the connection
    """
    # Get the stored state from the session
    state_data = session.get("auth_state_data")
    if not state_data:
        raise Exception("No auth state data found in session")

    # Inject into state store manually
    await auth0_backend.state_store.set(auth0_backend.state_identifier, state_data)

    return await auth0_backend.get_access_token_for_connection({
        "connection": "kp-oidc",
        "scope": "openid profile email offline_access"
    })

def get_tokenset():
    """
    Get federated access token from token vault.
    
    Returns:
        str: Federated access token or None if retrieval fails
    """
    try:
        tokenset = asyncio.run(get_token_from_token_vault())
        print("##############")
        print('Token response:', tokenset)
        return tokenset
    except Exception as e:
        print(f"Error getting token from vault: {str(e)}")
        return None

@app.route("/chat", methods=["POST"])
@requires_auth
def chat():
    """
    Handle chat requests with Bedrock agent.
    
    Expects:
        - JSON payload with 'message' field
        - User must be authenticated
        
    Returns:
        - JSON response with agent's response
        - Session ID and request ID for tracking
    """
    try:
        # Get the federated token from token vault
        federated_token = get_tokenset()
        print('Federated token response:', federated_token)

        if not federated_token:
            return jsonify({"response": "Failed to obtain federated token. Please try logging in again."}), 401

        user_message = request.json.get("message", "")
        if not user_message:
            return jsonify({"response": "No message provided."}), 400

        # Create a new session ID for this conversation
        session_id = str(uuid.uuid4())

        # Prepare the session state with the federated token
        session_state = {
            "sessionAttributes": {
                "refresh_token": session['refresh_token'],
                "federated_token": federated_token,
                "logged_in_user": session['profile']['email'],
                "user_id": session['profile']['user_id']
            }
        }

        print('Session state:', session_state)

        # Invoke the Bedrock agent
        response = bedrock.invoke_agent(
            agentId=BEDROCK_AGENT_ID,
            agentAliasId=BEDROCK_AGENT_ALIAS_ID,
            sessionId=session_id,
            inputText=user_message,
            enableTrace=True,
            sessionState=session_state
        )

        # Log action trace information
        trace = response.get('trace', [])
        for step in trace:
            if step.get('type') == 'InvokeAction':
                action_group = step.get('actionGroup')
                function_name = step.get('function')
                parameters = step.get('parameters', [])
                print(f"Action Group: {action_group}")
                print(f"Function: {function_name}")
                print(f"Parameters: {parameters}")

        # Process the response
        completion = []
        for event in response.get('completion', []):
            if 'chunk' in event:
                try:
                    chunk_bytes = event['chunk']['bytes']
                    chunk_str = chunk_bytes.decode('utf-8')
                    print('Chunk:', chunk_str)
                    completion.append(chunk_str)
                except json.JSONDecodeError as je:
                    print(f"JSON decode error in chunk: {je}")
                    print(f"Raw chunk string: {chunk_str}")
                except Exception as e:
                    print(f"Error processing chunk: {str(e)}")

        # Combine the chunks of the response
        full_response = ''.join(completion)
        
        return jsonify({
            'response': full_response,
            'sessionId': session_id,
            'requestId': response.get('requestId')
        })

    except Exception as e:
        print(f"Error in chat endpoint: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({"response": f"Error: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True)