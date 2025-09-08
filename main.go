package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	httpAddr          = "localhost:7777"
	mcpPath           = "/mcp"
	protectedResource = "http://" + httpAddr + mcpPath
	resourceMetaURL   = "http://" + httpAddr + defaultProtectedResourceMetadataURI + mcpPath
	clientID          = "mcp-inspector"
	scopesSupported   = []string{"email", "profile"}
	keycloakURL       = "http://localhost:8090/realms/mcp-realm"
	JWKSURI           = keycloakURL + "/protocol/openid-connect/certs"
)

type JWTClaims struct {
	UserID string   `json:"user_id"`
	Scopes []string `json:"scopes"`
	jwt.RegisteredClaims
}

type Verifier struct {
	Scopes  []string
	UserID  string
	KeyFunc keyfunc.Keyfunc
}

func (v Verifier) verifyJWT(ctx context.Context, tokenString string, _ *http.Request) (*auth.TokenInfo, error) {
	log.Printf("verifier received token: %s", tokenString)
	claims := &JWTClaims{
		UserID: v.UserID,
		Scopes: v.Scopes,
	}
	token, err := jwt.ParseWithClaims(tokenString, claims, v.KeyFunc.Keyfunc)
	if err != nil {
		// panic to stop mcp inspector retrying forever
		log.Panicf("err: %v", err)
		return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return &auth.TokenInfo{
			Scopes:     claims.Scopes,
			Expiration: claims.ExpiresAt.Time,
		}, nil
	}

	return nil, fmt.Errorf("%w: invalid token claims", auth.ErrInvalidToken)
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "echo", Title: "Echo Server"}, nil)

	type args struct {
		Input string `json:"input" jsonschema:"the input to be echoed"`
	}

	mcp.AddTool(server, &mcp.Tool{
		Name:        "echo",
		Description: "echo input back",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args args) (*mcp.CallToolResult, any, error) {
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
		log.Panicf("creating keyfunc", err)
	}

	verifier := Verifier{
		Scopes:  scopesSupported,
		UserID:  clientID,
		KeyFunc: keyFunc,
	}

	authMiddleware := auth.RequireBearerToken(verifier.verifyJWT, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: resourceMetaURL,
		Scopes:              scopesSupported,
	})

	authenticatedHandler := authMiddleware(handler)
	http.HandleFunc(mcpPath, authenticatedHandler.ServeHTTP)

	// handler for resourceMetaURL
	http.HandleFunc(defaultProtectedResourceMetadataURI+mcpPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")                     // for mcp-inspector
		w.Header().Set("Access-Control-Allow-Headers", "mcp-protocol-version") // for mcp-inspector
		prm := &ProtectedResourceMetadata{
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
