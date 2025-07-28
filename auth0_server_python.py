import os
import asyncio
import uuid

from auth0_server_python.auth_server import ServerClient
from flask import Blueprint, request, session, make_response, url_for, Flask, redirect
from dotenv import load_dotenv
from auth0_server_python.auth_types import StartInteractiveLoginOptions, LogoutOptions
from stores import FlaskCookieTransactionStore, FlaskStatelessStateStore

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", "your-secret-key-here")
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Auth0 Configuration
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
AUTH0_SECRET = os.getenv("AUTH0_SECRET", "your-auth0-secret")
CALLBACK_URL = os.getenv("AUTH0_CALLBACK_URL", "http://localhost:5000/callback")

auth0 = ServerClient(
    domain=AUTH0_DOMAIN,
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    authorization_params={"scope": "openid profile email offline_access"},
    redirect_uri=f"{os.getenv('APP_BASE_URL', 'http://localhost:5000')}/auth/callback",
    transaction_store=FlaskCookieTransactionStore(secret=app.secret_key),
    state_store=FlaskStatelessStateStore(secret=app.secret_key),
    secret=app.secret_key
)

login_bp = Blueprint("auth0", __name__)

@login_bp.route("/auth/login")
async def login():
    response = make_response()
    store_options = {"request": request, "response": response}
    options = StartInteractiveLoginOptions(
        app_state={"returnTo": request.args.get("returnTo")},
        authorization_params={k: v for k, v in request.args.items() if k != "returnTo"}
    )

    response.headers["Location"] = await auth0.start_interactive_login(options, store_options)
    response.status_code = 302
    return response

@login_bp.route("/auth/callback")
async def login_callback():
    response = make_response()
    store_options = {"request": request, "response": response}
    default_return_to = url_for("home", _external=True)

    result = await auth0.complete_interactive_login(str(request.url), store_options)
    session["user"] = result.get("state_data", {}).get("user")

    response.headers["Location"] = result["app_state"].get("returnTo") or default_return_to
    response.status_code = 302
    return response

@login_bp.route("/auth/logout")
async def logout():
    response = make_response()
    store_options = {"request": request, "response": response}
    options = LogoutOptions(return_to=url_for("home", _external=True))

    response.headers["Location"] = await auth0.logout(options, store_options)
    response.status_code = 302
    session.clear()
    return response

# Register blueprint AFTER defining all its routes
app.register_blueprint(login_bp)

@app.route("/")
async def home():
    if "user" not in session:
        return redirect(url_for("auth0.login", _external=True))

    session["thread_id"] = str(uuid.uuid4())
    return f"Welcome {session['user'].get('name')}! Your session is ready."

if __name__ == "__main__":
    app.run(debug=True)
