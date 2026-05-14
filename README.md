# mcp-auth-go-sdk

Testing oauth support from [go-sdk](https://github.com/modelcontextprotocol/go-sdk) with Keycloak and [MCP Inspector](https://github.com/modelcontextprotocol/inspector). This is not production ready.

## Keycloak
See [Keycloak MCP support](https://www.keycloak.org/securing-apps/mcp-authz-server). Tested with Keycloak v26.2.1.
```
$ podman run -d \
  --name keycloak-http \
  -p 8090:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

Create a realm, client, users, scopes, roles, mappings:
```
$ uv run --with python-keycloak setup-keycloak.py
```

## MCP server
```
$ go run .
```

## MCP client
Use [this](https://github.com/djoreilly/mcp-oauth-client/tree/main) MCP client:

```
$ CLIENT_ID=mcp-test-client CLIENT_SECRET=secret ./mcp-cli --server-url http://localhost:7777/mcp
Connecting to MCP server...
Please open the following URL in your browser: http://localhost:8090/realms/mcp-realm/protocol/openid-connect/auth?client_id=mcp-test-client&code_challenge=ESpw0QNnZzJ0J56mPTM9v4S9Ia7YrPQuuVCSxFJLa0g&code_challenge_method=S256&redirect_uri=http%3A%2F%2Flocalhost%3A3142&resource=http%3A%2F%2Flocalhost%3A7777%2Fmcp&response_type=code&scope=mcp%3Atools%3Aread+mcp%3Atools%3Awrite&state=3FOF7URSAHKGTQDCXV3HWAKQEU
Connected to MCP server

Interactive MCP Client
Commands:
  list - List available tools
  call <tool_name> [args] - Call a tool
  quit - Exit the client

mcp> list

Available tools:
1. echo
   echo input back
2. to_upper
   returns the input string in uppercase
mcp>
mcp> call echo {"input": "fasdfasdf"}

Tool 'echo' result:
fasdfasdf
```

## MCP Inspector
This tool is very finicky to use and get working with oauth.
Use 0.16.7 as 0.16.8 is [broken](https://github.com/modelcontextprotocol/inspector/issues/824).

In the Keycloak UI, navigate to the mcp-test-client and set "Web Origins" to `*` and "Valid Redirect URIs" to `http://localhost:6274/oauth/callback*` - these are needed for mcp-inspector.
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
