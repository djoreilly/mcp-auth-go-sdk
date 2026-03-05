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
