import os
import json
from functools import wraps
from traceback import print_exc

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import boto3
import requests
from os import environ as env

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
    Stores user information and tokens in session.
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

        # Store the tokens
        session['user'] = token
        if "refresh_token" in token:
            session["refresh_token"] = token["refresh_token"]
            print("Stored refresh token in session")
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

def get_tokenset():
    """
    Exchange refresh token for federated access token.
    
    Returns:
        str: Federated access token or None if exchange fails
    """
    if not session.get("refresh_token"):
        print("No refresh token available in session")
        return None

    url = f"https://{env.get('AUTH0_DOMAIN')}/oauth/token"
    headers = {"content-type": "application/json"}
    payload = {
        "client_id": env.get("AUTH0_CLIENT_ID"),
        "client_secret": env.get("AUTH0_CLIENT_SECRET"),
        "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
        "subject_token": session["refresh_token"],
        "connection": "<<Connection Name from Auth0>>",
        "audience": f"https://{env.get('AUTH0_DOMAIN')}/api/v2/",
        "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
        "scope": "okta.users.read okta.users.read.self"
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        tokenset = response.json()
        return tokenset.get("access_token")
    except requests.exceptions.RequestException as e:
        error_text = e.response.text if hasattr(e, 'response') else "No response"
        print("Error getting token:", error_text)
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
        # Get the federated token
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