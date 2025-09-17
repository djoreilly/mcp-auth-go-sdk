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

## MCP Inspector
```
$ npx @modelcontextprotocol/inspector@latest
```
Open the `Authentication` dropdown on the left and set:

	Transport Type: `Streamable HTTP`
	URL: `http://localhost:7777/mcp`
	Client ID: `mcp-test-client`
	Scope: `mcp:read mcp:tools mcp:prompts`
	Bearer Token: make sure this is really empty. Select all the `*`s, press delete and press escape.

Presss `Connect` and a browser should popup a form to authenticate with Keycloak.

## Troubleshooting
If things break, use "Clear OAuth State" from "Open Auth Settings" in Inspector.
Look for errors in the browser console and the Keycloak logs.

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
    "mcp:read",
    "mcp:tools",
    "mcp:prompts"
  ],
  "bearer_methods_supported": [
    "header"
  ]
}
```
