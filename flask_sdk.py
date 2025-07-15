import asyncio
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
from auth0_server_python.auth_server import ServerClient

import uuid

from six import print_
########### STILL WORK IN PROGRESS ... DON'T USE THIS CODE ##########
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "your-random-secret-key")
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"

# Auth0 config
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
AUTH0_BASE_URL = f"https://{AUTH0_DOMAIN}"
AUTH0_CALLBACK_URL = os.getenv("AUTH0_CALLBACK_URL", "http://127.0.0.1:5000/callback")

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
    def __init__(self):
        self.store = {}

    async def set(self, key, value, options=None):
        self.store[key] = value

    async def get(self, key, options=None):
        return self.store.get(key)

    async def delete(self, key, options=None):
        if key in self.store:
            del self.store[key]

auth01 = ServerClient(
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
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

# AWS Bedrock setup
bedrock = boto3.client(
    service_name="bedrock-agent-runtime",
    region_name=os.getenv("AWS_DEFAULT_REGION"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
)
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0")

@app.route("/login")
def login():
    # Clear any existing session data before starting new auth flow
    session.clear()
    return auth0.authorize_redirect(
        redirect_uri=AUTH0_CALLBACK_URL,
        response_type='code'
    )

@app.route("/callback")
def callback():
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
            asyncio.run(auth01.state_store.set(auth01.state_identifier,
                {"refresh_token": token["refresh_token"],"connection_token_sets": []}))
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
    session.clear()
    return redirect(
        f"{AUTH0_BASE_URL}/v2/logout?returnTo={url_for('index', _external=True)}&client_id={AUTH0_CLIENT_ID}"
    )

@app.route("/")
@requires_auth
def index():
    return render_template("index.html", user=session['profile'])

def get_completion_from_response(response):
    completion = ""

    for event in response.get("completion"):
        chunk = event["chunk"]
        completion += chunk["bytes"].decode()

    return completion

async def get_token_from_token_vault():
    return await auth01.get_access_token_for_connection(
        options = {
            "connection" : "kp-oidc",
            "scope" : "openid profile email offline_access"})

def get_tokenset():

    '''url = f"https://{env.get('AUTH0_DOMAIN')}/oauth/token"
    headers = {"content-type": "application/json"}
    payload = {
        "client_id": env.get("AUTH0_CLIENT_ID"),
        "client_secret": env.get("AUTH0_CLIENT_SECRET"),
        "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
        "subject_token": session["refresh_token"],
        "connection": "<<Connection-Name>>",
        "audience": f"https://{env.get('AUTH0_DOMAIN')}/api/v2/",
        "requested_token_type": "http://auth0.com/oauth/token-type/federated-connection-access-token",
        "scope": "okta.users.read okta.users.read.self"
    }
    '''
    try:
        tokenset=asyncio.run(get_token_from_token_vault())
        print("##############")
        print('Token response:', tokenset)
        return tokenset
    except requests.exceptions.RequestException as e:
        error_text = e.response.text if hasattr(e, 'response') else "No response"
        print("Error getting token:", error_text)
        return None


@app.route("/chat", methods=["POST"])
@requires_auth
def chat():
    try:
        # Get the federated token
        federated_token = get_tokenset()
        ('Federated token response:', federated_token)

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
                "refresh_token": session['refresh_token'] ,
                "federated_token":federated_token ,
                "logged_in_user": session['profile']['email'] ,# Ensure token is sent as string
                "user_id":session['profile']['user_id']
            }
        }

        print('Session state:', session_state)

        # Invoke the Bedrock agent
        response = bedrock.invoke_agent(
            agentId="XXXX",
            agentAliasId="XXXX",
            sessionId=session_id,
            inputText=user_message,
            enableTrace=True,
            sessionState=session_state
        )
        print('#################################')
        trace = response.get('trace', [])
        for step in trace:
            if step.get('type') == 'InvokeAction':
                action_group = step.get('actionGroup')
                function_name = step.get('function')
                parameters = step.get('parameters', [])
                print(f"Action Group: {action_group}")
                print(f"Function: {function_name}")
                print(f"Parameters: {parameters}")

        print('#################################')
        #print('Bedrock response:', response)

        # Process the response
        completion = []
        for event in response.get('completion', []):
            if 'chunk' in event:
                try:
                    chunk_bytes = event['chunk']['bytes']
                    chunk_str = chunk_bytes.decode('utf-8')
                    #print('Chunk string:', chunk_str)
                    #chunk = json.loads(chunk_str)
                    print('Chunk:', chunk_str)
                    completion.append(chunk_str)
                    #if 'content' in chunk:
                    #    completion.append(chunk['content'])
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