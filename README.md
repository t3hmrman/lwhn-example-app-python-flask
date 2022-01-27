# LoginWithHN OAuth2+OpenID Connect example (Python + Flask)

This repository contains code [heavily inspired by `shihanng/flask-login-example`](https://github.com/shihanng/flask-login-example) which displays how to implement the login flow for [LoginWithHN](https://loginwithhn.com).

# Context: the OAuth2/OpenID Connect Login process

IF you need more information on the login process, check out the following links:

- https://developer.okta.com/blog/2019/10/21/illustrated-guide-to-oauth-and-oidc
- https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow
- https://www.pingidentity.com/en/resources/client-library/articles/openid-connect.html
- https://darutk.medium.com/diagrams-and-movies-of-all-the-oauth-2-0-flows-194f3c3ade85

LoginWithHN is an OAuth2+OpenID Connect provider that authenticates users **via [HackerNews][hn]**. LWHN *does not* replace your apps login process (you still need to save cookies or JWTs for your site), but it can authenticate a single user via HN username (you will have access to their username).

# Getting started

## 1. Create an OAuth2+OpenID Connect Application on [LoginWithHN][lwhn]

## 2. Clone this repo

## 3. Setup this repo

After cloning this repo, to run the code:

```console
$ # Create a python virtual environment, install requirements
$ python3 -mvenv env
$ pip install --editable .
```

## 4. Run the login app

```console
$ # Set the environment variables for your app
$ export LWHN_APP_CLIENT_ID=< value from loginwithhn.com >
$ export LWHN_APP_CLIENT_SECRET=< value from loginwithhn.com >
$ export APP_HOSTNAME=where-you-hosted-it.com # ex: http://localhost:5000

$ # Run the app (the virtual env should be loaded)
$ export FLASK_APP=src/simple_login/app.py
$ flask run
```

After the app is running, view it in your browser at `http://localhost:5000`

[lwhn]: https://loginwithhn.com
