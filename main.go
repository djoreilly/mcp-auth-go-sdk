package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

const (
	defaultProtectedResourceMetadataURI = "/.well-known/oauth-protected-resource"
)

var (
	httpAddr          = "localhost:7777"
	mcpPath           = "/mcp"
	protectedResource = "http://" + httpAddr + mcpPath
	resourceMetaURL   = "http://" + httpAddr + defaultProtectedResourceMetadataURI + mcpPath
	audience          = "echo-mcp-server"
	// scopesSupported   = []string{"mcp:read", "mcp:tools", "mcp:prompts"} // mcp-admin
	scopesSupported = []string{"mcp:read", "mcp:tools"} // mcp-user
	keycloakURL     = "http://localhost:8090/realms/mcp-realm"
	// keycloakURL = "http://leap16.kvm:8080/realms/mcp-realm"
	JWKSURI = keycloakURL + "/protocol/openid-connect/certs"
)

type Verifier struct {
	KeyFunc keyfunc.Keyfunc
}

func (v Verifier) verifyJWT(_ context.Context, tokenString string, _ *http.Request) (*auth.TokenInfo, error) {
	log.Printf("verifier received token: %s", tokenString)

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, &claims, v.KeyFunc.Keyfunc, jwt.WithAudience(audience),
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Name}))
	if err != nil {
		// Uncomment panic to stop mcp inspector spinning sometimes - it's tedious to kill/restart.
		// Rate limiting middleware is needed to protect against buggy/misbehaving clients.
		// See go-sdk examples/server/rate-limiting/.
		// log.Panicf("err: %v", err)
		return nil, fmt.Errorf("%v: %w", auth.ErrInvalidToken, err)
	}
	for k, v := range claims {
		log.Printf("claim: %v: %v", k, v)
	}
	if token.Valid {
		expireTime, err := claims.GetExpirationTime()
		if err != nil {
			return nil, fmt.Errorf("%v: %w", auth.ErrInvalidToken, err)
		}
		scopes, ok := claims["scope"].(string)
		if !ok {
			return nil, fmt.Errorf("unable to type assert scopes: %w", auth.ErrInvalidToken)
		}
		return &auth.TokenInfo{
			Scopes:     strings.Split(scopes, " "),
			Expiration: expireTime.Time,
		}, nil
	}
	return nil, auth.ErrInvalidToken
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "echo", Title: "Echo Server"}, nil)

	type args struct {
		Input string `json:"input" jsonschema:"the input to be echoed"`
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "echo",
		Description: "echo input back",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args args) (*mcp.CallToolResult, any, error) {
		tokenInfo := auth.TokenInfoFromContext(ctx)
		log.Printf("Scopes: %v", tokenInfo.Scopes)
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: args.Input},
			},
		}, nil, nil
	})

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, nil)

	// starts a goroutine in background to download JWK Set and keep it refreshed
	keyFunc, err := keyfunc.NewDefaultCtx(context.Background(), []string{JWKSURI})
	if err != nil {
		log.Panicf("creating keyfunc: %v", err)
	}

	verifier := Verifier{
		KeyFunc: keyFunc,
	}

	authMiddleware := auth.RequireBearerToken(verifier.verifyJWT, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: resourceMetaURL,
		Scopes:              scopesSupported,
	})

	authenticatedHandler := authMiddleware(handler)
	http.HandleFunc(mcpPath, authenticatedHandler.ServeHTTP)

	// handler for resourceMetaURL
	http.HandleFunc(defaultProtectedResourceMetadataURI+mcpPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")                     // for mcp-inspector
		w.Header().Set("Access-Control-Allow-Headers", "mcp-protocol-version") // for mcp-inspector
		prm := &oauthex.ProtectedResourceMetadata{
			Resource:               protectedResource,
			AuthorizationServers:   []string{keycloakURL},
			ScopesSupported:        scopesSupported,
			BearerMethodsSupported: []string{"header"},
			JWKSURI:                JWKSURI,
		}
		if err := json.NewEncoder(w).Encode(prm); err != nil {
			log.Panic(err)
		}
	})

	log.Print("MCP server listening on ", protectedResource)
	if err := http.ListenAndServe(httpAddr, nil); err != nil {
		log.Panic(err)
	}
}
