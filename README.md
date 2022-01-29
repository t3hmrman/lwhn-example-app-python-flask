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
$ export APP_HOSTNAME=where-you-hosted-it.com # ex: http://localhost:5000 ('/callback' will be added by the app)

$ # Run the app (the virtual env should be loaded)
$ flask run -h localhost
```

After the app is running, view it in your browser at `http://localhost:5000`

# FAQ

## ERROR: CSRF Value from teh token does not match

If you get a redirect like this:

```
127.0.0.1 - - [28/Jan/2022 01:14:13] "GET /callback?error=request_forbidden&error_description=The+request+is+not+allowed.+The+CSRF+value+from+the+token+does+not+match+the+CSRF+value+from+the+data+store.&state=00e2bb58970e339e760ebb1d4958f97cd7c34f52628609f978eec79b7336832c HTTP/1.1" 401 -
```

Make sure that the URL you used for your app *matches the server exactly*. For example, if you ask for a callback URL of `http://localhost:5000` but your server is running as `http://127.0.0.1:5000`, **you must use the same URL in both places**. `localhost` and `127.0.0.1` may resolve to the same place, but they're not the same URL in terms of cookies.

It may help to manually clear cookies on `localhost` (specifically `oauth2_authentication_csrf_insecure`)

See: [Hydra Common CSRF mistakes](https://www.ory.sh/hydra/docs/debug/csrf/#mixing-up-127001-and-localhost)
See: [comment in ory/hydra issue #1647](https://github.com/ory/hydra/issues/1647#issuecomment-558169277)

## ERROR: No CSRF value available in the session cookie

Ensure you are not in a private window -- you can't run the LWHN OAuth2 flow in a private window.

See: [Hydra Common CSRF mistakes](https://www.ory.sh/hydra/docs/debug/csrf/#mixing-up-127001-and-localhost)
See [comment in ory/hydra issue #1647](https://github.com/ory/hydra/issues/1647#issuecomment-558169277)

[lwhn]: https://loginwithhn.com
