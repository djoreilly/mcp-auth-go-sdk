# mcp-auth-go-sdk

Testing oauth support from [go-sdk](https://github.com/modelcontextprotocol/go-sdk) with Keycloak and [MCP Inspector](https://github.com/modelcontextprotocol/inspector).

## Keycloak
```
$ podman run -d \
  --name keycloak-http \
  -p 8090:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

Use this [script](https://github.com/djoreilly/mcp-auth-step-by-step/blob/fixes/keycloak/setup_keycloak.py) to setup a realm, client, scopes, scope mapper and some users in Keycloak.

In the Keycloak UI, navigate to the mcp-test-client and set "Web Origins" to `*` and "Valid Redirect URIs" to `http://localhost:6274/oauth/callback*` - these are needed for mcp-inspector.

## MCP server
```
$ go run .
```

## MCP client
Use this [example oauth client](https://github.com/modelcontextprotocol/go-sdk/blob/16d990b0416f63ca4948a5d8ba8f54ac6114b5a9/examples/auth/client/main.go) from the `go-sdk`.
You can enable `Client authentication` for `mcp-test-client` in the Keycloak UI if you want, and copy the `Client Secret` from the Credientals tab. Then uncomment and edit [these lines](https://github.com/modelcontextprotocol/go-sdk/blob/16d990b0416f63ca4948a5d8ba8f54ac6114b5a9/examples/auth/client/main.go#L90-L95).

```
~/go-sdk> GOFLAGS="-tags=mcp_go_client_oauth" go run examples/auth/client/main.go -server_url http://localhost:7777/mcp
Please open the following URL in your browser: http://localhost:8090/realms/mcp-realm/protocol/openid-connect/auth?client_id=mcp-test-client&code_challenge=qC-3MpNezRuJdex0i01x571fKYA5CLKmYYLzwYsoOd4&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A3142&resource=http%3A%2F%2Flocalhost%3A7777%2Fmcp&response_type=code&scope=mcp%3Atools%3Aread+mcp%3Atools%3Awrite&state=TBTXOSHCR73VV43BXRDSKR62NB
2026/03/05 13:10:36 Tools:
2026/03/05 13:10:36 - "echo"
2026/03/05 13:10:36 - "to_upper"
```

## MCP Inspector
This tool is very finicky to use and get working with oauth.
Use 0.16.7 as 0.16.8 is [broken](https://github.com/modelcontextprotocol/inspector/issues/824).
```
$ npx @modelcontextprotocol/inspector@0.16.7
```
Open the `Authentication` dropdown on the left and set:

	Transport Type: `Streamable HTTP`
	URL: `http://localhost:7777/mcp`
	Client ID: `mcp-test-client`
	Scope: `mcp:tools:read mcp:tools:write`
	Bearer Token: make sure this is really empty. Select all the `*`s, press delete and press escape.

Presss `Connect` and a browser should popup a form to authenticate with Keycloak. User `mcp-user/user123` or `mcp-admin/admin123`.

## Troubleshooting
If things break, use "Clear OAuth State" from "Open Auth Settings" in Inspector.
Look for errors in the browser console and the Keycloak logs: `podman logs keycloak-http`.

```
$ curl -sv http://localhost:7777/mcp 2>&1 | grep -i auth
< HTTP/1.1 401 Unauthorized
< Www-Authenticate: Bearer resource_metadata=http://localhost:7777/.well-known/oauth-protected-resource/mcp
```

```
$ curl -s http://localhost:7777/.well-known/oauth-protected-resource/mcp | jq .
{
  "resource": "http://localhost:7777/mcp",
  "authorization_servers": [
    "http://localhost:8090/realms/mcp-realm"
  ],
  "jwks_uri": "http://localhost:8090/realms/mcp-realm/protocol/openid-connect/certs",
  "scopes_supported": [
    "mcp:tools:read",
    "mcp:tools:write"
  ],
  "bearer_methods_supported": [
    "header"
  ]
}
```
Use tcpflow to see the traffic:
```
# tcpflow -c -i lo port 7777
```
Use [https://www.jwt.io/](https://www.jwt.io/) to decode JWTs.

## Kanidm
This is an attempt to use [Kanidm](https://kanidm.com/) as the Oauth2 Authorization Server. Follow the [kanidm doc](https://kanidm.github.io/kanidm/stable/installing_the_server.html) to install the Kanidm server.

Create a client:
```bash
$ kanidm system oauth2 create mcp-test-client "mcp test client" http://localhost:7777/mcp
```

Get the client secret:
```bash
$ kanidm system oauth2 show-basic-secret mcp-test-client
yzk94kpwq7qb2gghe6xqz0ujbdpws51asatabg3qqqvjvgqv
```

Set the client's redirect-url for the [MCP client](https://github.com/djoreilly/mcp-oauth-client/blob/30bfaeb3cf679313a683b22f0cc3b3510b218395/main.go#L55):
```bash
$ kanidm system oauth2 add-redirect-url mcp-test-client http://localhost:3142/
```

[Create an account](https://kanidm.github.io/kanidm/stable/evaluation_quickstart.html#create-an-account-for-yourself), e.g. `doreilly`, a group `mcp`, and add the account to it:
```bash
$ kanidm group create mcp
$ kanidm group add-members mcp doreilly
```

Add scopes to the `mcp` group (Kanidm doesn't allow `:` in scopes):
```bash
$ kanidm system oauth2 update-scope-map mcp-test-client mcp email profile openid
$ kanidm system oauth2 update-sup-scope-map mcp-test-client mcp mcp_tools_read mcp_tools_write
```

Start the MCP and run the [client](https://github.com/djoreilly/mcp-oauth-client/tree/main) and authenticate as the account you created:
```bash
$ CLIENT_ID=mcp-test-client \
  CLIENT_SECRET=yzk94kpwq7qb2gghe6xqz0ujbdpws51asatabg3qqqvjvgqv \
  GOFLAGS="-tags=mcp_go_client_oauth" \
  go run main.go --server-url http://localhost:7777/mcp \
Connecting to MCP server...
Please open the following URL in your browser: https://orion.kvm:8443/ui/oauth2?client_id=mcp-test-client&code_challenge=BquwX8u7MU3pgrBuQJPJFNoBL7w-s7-vkolU4obz0es&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A3142&resource=http%3A%2F%2Flocalhost%3A7777%2Fmcp&response_type=code&scope=email+openid+profile&state=6GQLHDBR5MPMFTNRTRXQLG2E3P
```

In this example the client is setting the `resource` parameter to `http://localhost:7777/mcp` in requests to Kanidm. The MCP spec [says](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#token-audience-binding-and-validation) that the MCP server **MUST** validate that the tokens were issued for them. But Kanimd doesn't support [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html) and sets the `aud` claim to the `client_id`, and not the `resource` parameter that was sent to it. So this example does not do audience validation.
