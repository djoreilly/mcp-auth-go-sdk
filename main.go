package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

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
	scopesSupported   = []string{"mcp:tools:read", "mcp:tools:write"}
	keycloakURL       = "http://localhost:8090/realms/mcp-realm"
	// keycloakURL = "http://leap16.kvm:8080/realms/mcp-realm"
)

var requiredToolScopes = map[string][]string{
	"echo":     {"mcp:tools:read"},
	"to_upper": {"mcp:tools:read", "mcp:tools:write"},
}

// getJwksUri gets the jwks_uri from the OpenID Provider configuration information.
// See https://openid.net/specs/openid-connect-discovery-1_0.html
func getJwksURI(issuer string) (string, error) {
	resp, err := http.Get(issuer + "/.well-known/openid-configuration")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	openIDConfig := struct {
		JwksURI string `json:"jwks_uri"`
	}{}

	err = json.NewDecoder(resp.Body).Decode(&openIDConfig)
	if err != nil {
		return "", err
	}

	return openIDConfig.JwksURI, nil
}

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

func userHasRequiredScopes(userScopes []string, requiredScopes []string) bool {
	for _, requiredScope := range requiredScopes {
		if !slices.Contains(userScopes, requiredScope) {
			return false
		}
	}
	return true
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{Name: "string utils", Title: "string utils"}, nil)

	// middleware intercepts tools/list response and removes tools the user doesn't have scopes for.
	filterTools := func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			resp, err := next(ctx, method, req)
			if err != nil {
				return resp, err
			}
			if listToolResult, ok := resp.(*mcp.ListToolsResult); ok {
				userScopes := auth.TokenInfoFromContext(ctx).Scopes
				filteredTools := []*mcp.Tool{}
				for _, tool := range listToolResult.Tools {
					requiredScopes := requiredToolScopes[tool.Name]
					if userHasRequiredScopes(userScopes, requiredScopes) {
						filteredTools = append(filteredTools, tool)
					}
				}
				listToolResult.Tools = filteredTools
			}
			return resp, nil
		}
	}

	checkToolCallScopes := func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if callToolRequest, ok := req.(*mcp.CallToolRequest); ok {
				requiredScopes := requiredToolScopes[callToolRequest.Params.Name]
				userScopes := auth.TokenInfoFromContext(ctx).Scopes
				if !userHasRequiredScopes(userScopes, requiredScopes) {
					// NOTE: does not conform with
					// https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization#runtime-insufficient-scope-errors
					return nil, fmt.Errorf("insufficent scope")
				}
			}
			return next(ctx, method, req)
		}
	}

	server.AddReceivingMiddleware(filterTools, checkToolCallScopes)

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

	mcp.AddTool(server, &mcp.Tool{
		Name:        "to_upper",
		Description: "returns the input string in uppercase",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args args) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: strings.ToUpper(args.Input)},
			},
		}, nil, nil
	})

	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return server
	}, nil)

	jwksURI, err := getJwksURI(keycloakURL)
	if err != nil {
		log.Fatalf("getting JWKS URI: %v", err)
	}

	// starts a goroutine in background to download JWK Set and keep it refreshed
	keyFunc, err := keyfunc.NewDefaultCtx(context.Background(), []string{jwksURI})
	if err != nil {
		log.Panicf("creating keyfunc: %v", err)
	}

	verifier := Verifier{
		KeyFunc: keyFunc,
	}

	authMiddleware := auth.RequireBearerToken(verifier.verifyJWT, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: resourceMetaURL,
	})

	authenticatedHandler := authMiddleware(handler)
	http.HandleFunc(mcpPath, authenticatedHandler.ServeHTTP)

	prm := &oauthex.ProtectedResourceMetadata{
		Resource:             protectedResource,
		AuthorizationServers: []string{keycloakURL},
		ScopesSupported:      scopesSupported,
	}
	http.Handle(defaultProtectedResourceMetadataURI+mcpPath, auth.ProtectedResourceMetadataHandler(prm))

	log.Print("MCP server listening on ", protectedResource)
	s := &http.Server{
		Addr:              httpAddr,
		ReadHeaderTimeout: 3 * time.Second,
	}
	if err := s.ListenAndServe(); err != nil {
		log.Panic(err)
	}
}
