import attr
import os
import base64
import json
import random
import hashlib
import requests
import time
import logging

from flask import Flask, session, current_app, render_template, redirect
from flask import make_response, request, Response
from flask_session import Session
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from urllib.parse import urlencode

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
LWHN_OAUTH2_LOGOUT_URL = 'https://hydra.loginwithhn.com/oauth2/sessions/logout'

LWHN_APP_CLIENT_ID = os.environ.get("LWHN_APP_CLIENT_ID", default="")
LWHN_APP_CLIENT_SECRET = os.environ.get("LWHN_APP_CLIENT_SECRET", default="")

APP_HOSTNAME = os.environ.get("APP_HOSTNAME", default="http://localhost:5000")
APP_COOKIE_SECRET_KEY = os.environ.get("APP_COOKIE_SECRET_KEY", default="super-secret")

SESSION_TYPE = 'filesystem'

# Build the flask app
app = Flask(__name__,
            static_url_path='',
            static_folder='static')
app.logger.setLevel(logging.DEBUG)

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
    hn_username: str = attr.ib()
    karma: int = attr.ib()
    id_token: str = attr.ib()

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
        'scope':         'openid',
        'redirect_uri':  current_app.config["APP_HOSTNAME"]+'/callback',
        'state':         state,
        'nonce':         nonce,
    }

    # Redirect to LoginWithHN to kick off the login process
    redirect_url = LWHN_OAUTH2_AUTH_URL + '?' + urlencode(payload)

    app.logger.debug("session id is [%s]", session.sid)
    app.logger.debug("redirecting to url [%s]", redirect_url)

    return redirect(redirect_url)

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
        'client_id':     current_app.config["LWHN_APP_CLIENT_ID"],
        'code':          code,
        'redirect_uri':  current_app.config["APP_HOSTNAME"]+'/callback',
        'grant_type':    'authorization_code',
        'scope':         'openid',
    }

    # Client ID & Secret must be passed through via Basic Auth for LWHN Applications
    auth = (current_app.config["LWHN_APP_CLIENT_ID"], current_app.config["LWHN_APP_CLIENT_SECRET"])

    # Exchange code for an OAuth2 Token
    r = requests.post(LWHN_OAUTH2_TOKEN_ENDPOINT, payload, auth=auth)
    if r.status_code != requests.codes.ok:
        response = make_response(json.dumps('Got error from LWHN, See error log'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # 5. Obtain user information from the ID token
    resp_json = r.json()
    app.logger.debug("Received JSON from token endpoint : [%s]", json.dumps(resp_json, indent=2))

    # The ID token will come in as a very long JWT that we want to save (will be used at log out)
    id_token = resp_json['id_token']
    jwt = id_token.split('.')
    jwt_payload = json.loads(base64.b64decode(jwt[1] + "==="))
    app.logger.debug("Received jwt_payload: [%s]", json.dumps(jwt_payload, indent=2))

    # Ensure a nonce was provided
    if jwt_payload['nonce'] != session.pop('nonce', ''):
        response = make_response(json.dumps('Invalid nonce.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Ensure the audience is right (it should be your client app ID)
    if not current_app.config["LWHN_APP_CLIENT_ID"] in jwt_payload['aud']:
        response = make_response(json.dumps("Audience is missing app client ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Ensure the issuer is what we expect
    if jwt_payload['iss'] != 'https://loginwithhn.com/':
        response = make_response(json.dumps("Invalid issuer [{}].".format(jwt_payload['iss'])), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Save the user ID as the returned 'sub' claim (the HN username)
    user_id = jwt_payload['sub']

    # HN username
    hn_username = jwt_payload['username']

    # You can even grab the latest known karma count of the user
    karma = jwt_payload['metadata']['karma']

    # Create the user, save to in-memory user store
    u = User(user_id, hn_username=hn_username, karma=karma, id_token=id_token)
    app.logger.debug("Created user: {}".format(u))

    # Save the user to the in-memory user store (emptied out if the application is stopped)
    USER_STORE[user_id] = u

    # Log the user in with Flask-Login (setting cookies, etc)
    login_user(u)

    # Redirect to the secret part of the app if an error hasn't occurred
    return redirect(current_app.config["APP_HOSTNAME"] + '/secret');

@app.route("/secret", methods=['GET'])
@login_required
def secret() -> Response:
    """
    This is the endpoint that only logged in users can see
    """
    # current_user will be filled in by Flask-Login in the template
    return render_template('secret.html')

@app.route("/logout", methods=['GET'])
@login_required
def logout() -> Response:
    """
    Powers logout

    see: https://flask-login.readthedocs.io/en/latest/
    """

    # # If you wanted, you could logout the user right here and call it a day
    # logout_user()

    # [OPTIONAL] redirect to loginwithhn.com for logout, with a post_logout_redirect_uri
    state = hashlib.sha256(os.urandom(1024)).hexdigest()
    payload = {
        'id_token_hint':            current_user.id_token,
        'state':                    state,
        # After LWHN has logged out the user, it should redirect us back to our app
        # the post_logout_redirect_uri MUST be registered with LoginWithHN!
        # (if you don't specify a post logout redirect, users will be redirected to https://loginwithhn.com)
        'post_logout_redirect_uri': current_app.config["APP_HOSTNAME"] + '/logout/finish',
    }

    # Redirect to LoginWithHN to kick off the login process
    redirect_url = LWHN_OAUTH2_LOGOUT_URL + '?' + urlencode(payload)
    app.logger.debug("[logout] starting logout by redirecting to url [%s]", redirect_url)

    return redirect(redirect_url)

@app.route("/logout/finish", methods=['GET'])
def logout_finish() -> Response:
    """
    Finish logout (redirected to by your OAuth provider, in this case LoginWithHN)
    """
    logout_user()
    return redirect("/")

if __name__ == '__main__':
    app_host = os.environ.get("APP_LOCAL_HOSTNAME", default="localhost")
    app_port = os.environ.get("APP_LOCAL_PORT", default="5000")
    app.run(host=app_host, port=app_port)
