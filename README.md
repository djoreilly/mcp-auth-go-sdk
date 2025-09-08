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

To work with `main.go`, add a `mcp-realm` realm, and in it add a client `mcp-inspector` and a user for authenication.

## MCP server
```
$ go run .
```

## MCP Inspector
```
$ npx @modelcontextprotocol/inspector@latest
```
Open the `Authentication` dropdown on the left and set:
	URL: `http://localhost:7777/mcp`
	Client ID: `mcp-inspector`
	Scope: `email profile`
	Bearer Token: make sure this is really empty. Select all the `*`s, press delete and press escape.

Presss `Connect` and a browser should popup a form to authenticate with Keycloak.

If things break, use "Clear OAuth State" from "Open Auth Settings".
