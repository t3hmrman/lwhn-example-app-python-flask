import attr
import os
import base64
import json
import random
import hashlib
import requests
import time

from flask import Flask, session, current_app, render_template, redirect
from flask import make_response, request, Response
from flask_session import Session
from flask_login import LoginManager, login_required, login_user

from typing import Dict, Optional

###
###
### To use this application, you must:
### 1. Visit LoginWithHN (AKA "LWHN" @ https://loginwithhn.com) and log in
### 2. Create an OAuth2 Application
###    - carefully enter the callback URL for where this app is hosted (ex. 'domain.tld/callback', 'http://localhost:5000/callback')
###    - make sure to save your client ID and Secret when they are generated
### 3. Set LWHN_APP_CLIENT_ID and LWHN_APP_CLIENT_SECRET to the values you got from LWHN
### 3. Run this application (`make`, python app.py) this app and click Login
###
###

LWHN_OAUTH2_TOKEN_ENDPOINT = 'https://hydra.loginwithhn.com/oauth2/token'
LWHN_OAUTH2_AUTH_URL = 'https://hydra.loginwithhn.com/oauth2/auth'

LWHN_APP_CLIENT_ID = os.environ.get("LWHN_APP_CLIENT_ID", default="")
LWHN_APP_CLIENT_SECRET = os.environ.get("LWHN_APP_CLIENT_SECRET", default="")

APP_HOSTNAME = os.environ.get("APP_HOSTNAME", default="http://localhost:5000")
APP_COOKIE_SECRET_KEY = os.environ.get("APP_COOKIE_SECRET_KEY", default="super-secret")

SESSION_TYPE = 'filesystem'

# Build the flask app
app = Flask(__name__)

# Application configuration
app.config.from_object(__name__)
app.url_map.strict_slashes = False

# Flask session management (handles saving cookies)
Session(app)

# Login manager (Handles managing users)
login_manager = LoginManager()
login_manager.init_app(app)

###################
# User Management #
###################

@attr.s
class User(object):
    id = attr.ib()
    is_authenticated = True
    is_active = True
    is_anonymous = False

    def get_id(self):
        return self.id


USER_STORE: Dict[str, User] = {}

##############
# App Routes #
##############

@login_manager.user_loader
def load_user(user_id) -> Optional[User]:
    """
    Load a user
    """
    app.logger.debug('looking for user %s', user_id)
    u = USER_STORE.get(user_id, None)
    if not id:
        return None
    return u


def generate_nonce(length=8):
    """
    Generate pseudorandom number.
    """
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


@app.route("/", methods=['GET'])
def index() -> Response:
    """
    First page the use sees (your landing page)
    """
    return render_template('index.html')


@app.route("/login", methods=['GET'])
def login() -> Response:
    """
    Login endpoint that enables a login to happen
    """
    # 1. Create an anti-forgery state token
    state = hashlib.sha256(os.urandom(1024)).hexdigest()
    session['state'] = state

    nonce = generate_nonce()
    session['nonce'] = nonce

    # 2. Send an authentication request to LWHN
    payload = {
        'client_id':     current_app.config["LWHN_APP_CLIENT_ID"],
        'response_type': 'code',
        'scope':         'openid email',
        'redirect_uri':  current_app.config["APP_HOSTNAME"]+'/callback',
        'state':         state,
        'nonce':         nonce,
    }
    r = requests.get(LWHN_OAUTH2_AUTH_URL + '?', payload)

    # Print out the session ID being managed by Flask Session
    app.logger.debug('session id is %s', session.sid)

    return redirect(r.url)

@app.route("/callback", methods=['GET'])
def callback() -> Response:
    """
    Callback that is redirected to from LoginWithHN

    see: https://flask-login.readthedocs.io/en/latest/
    """
    # 3. Confirm anti-forgery state token
    if request.args.get('state', '') != session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # 4. Exchange code for access token and ID token
    code = request.args.get('code', '')
    payload = {
        'code':          code,
        'client_id':     current_app.config["LWHN_APP_CLIENT_ID"],
        'client_secret': current_app.config["LWHN_APP_CLIENT_SECRET"],
        'redirect_uri':  current_app.config["APP_HOSTNAME"]+'/callback',
        'grant_type':    'authorization_code',
    }

    r = requests.post(LWHN_OAUTH2_TOKEN_ENDPOINT, payload)
    if r.status_code != requests.codes.ok:
        response = make_response(json.dumps('Got error from LWHN.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    id_token = r.json()['id_token']

    # 5. Obtain user information from the ID token

    # TODO: Save the user's id token for later logout
    jwt = id_token.split('.')
    jwt_payload = json.loads(base64.b64decode(jwt[1] + "==="))

    if jwt_payload['nonce'] != session.pop('nonce', ''):
        response = make_response(json.dumps('Invalid nonce.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if jwt_payload['iss'] != 'https://accounts.google.com':
        response = make_response(json.dumps('Invalid issuer.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    user_id = 'google-' + jwt_payload['sub']

    # Create the user, save to in-memory user store
    u = User(user_id)
    USER_STORE[user_id] = u

    # Log the user in
    login_user(u)

    response = make_response(json.dumps(user_id))
    response.headers['Content-Type'] = 'application/json'
    return response

@app.route("/secret", methods=['GET'])
@login_required
def secret() -> Response:
    """
    This is the endpoint that only logged in users can see
    """
    return render_template('secret.html')

@app.route("/logout", methods=['GET'])
@login_required
def logout() -> Response:
    """
    Powers logout

    see: https://flask-login.readthedocs.io/en/latest/
    """
    logout_user()
    return redirect("/")
