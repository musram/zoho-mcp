package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// authKey is a custom context key for storing the auth token.
type authKey struct{}

// withAuthKey adds an auth key to the context.
func withAuthKey(ctx context.Context, auth string) context.Context {
	return context.WithValue(ctx, authKey{}, auth)
}

// authFromRequest extracts the auth token from the request headers.
func authFromRequest(ctx context.Context, r *http.Request) context.Context {
	return withAuthKey(ctx, r.Header.Get("Authorization"))
}

// authFromEnv extracts the auth token from the environment
func authFromEnv(ctx context.Context) context.Context {
	return withAuthKey(ctx, os.Getenv("API_KEY"))
}

// tokenFromContext extracts the auth token from the context.
// This can be used by tools to extract the token regardless of the
// transport being used by the server.
func tokenFromContext(ctx context.Context) (string, error) {
	auth, ok := ctx.Value(authKey{}).(string)
	if !ok {
		return "", fmt.Errorf("missing auth")
	}
	return auth, nil
}

type response struct {
	Args    map[string]interface{} `json:"args"`
	Headers map[string]string      `json:"headers"`
}

// makeRequest makes a request to httpbin.org including the auth token in the request
// headers and the message in the query string.
func makeRequest(ctx context.Context, message, token string) (*response, error) {
	log.Printf("Making request with message: %s, token: %s", message, token)

	// Create a new context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(timeoutCtx, "GET", "https://httpbin.org/anything", nil)
	if err != nil {
		log.Printf("Error creating request: %v", err)
		return nil, err
	}

	req.Header.Set("Authorization", token)
	query := req.URL.Query()
	query.Add("message", message)
	req.URL.RawQuery = query.Encode()

	log.Printf("Sending request to: %s", req.URL.String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("Error making request: %v", err)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return nil, err
	}

	log.Printf("Response status: %d, body: %s", resp.StatusCode, string(body))

	var r *response
	if err := json.Unmarshal(body, &r); err != nil {
		log.Printf("Error unmarshaling response: %v", err)
		return nil, err
	}

	return r, nil
}

// handleMakeAuthenticatedRequestTool is a tool that makes an authenticated request
// using the token from the context.
func handleMakeAuthenticatedRequestTool(
	ctx context.Context,
	request mcp.CallToolRequest,
) (*mcp.CallToolResult, error) {
	log.Printf("Tool request: %+v", request)

	// Extract message directly from Arguments
	message, ok := request.Params.Arguments["message"].(string)
	if !ok {
		return nil, fmt.Errorf("missing message in arguments")
	}

	token, err := tokenFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("missing token: %v", err)
	}

	// Now our tool can make a request with the token, irrespective of where it came from.
	resp, err := makeRequest(ctx, message, token)
	if err != nil {
		return nil, err
	}

	// Convert response to JSON string
	jsonResp, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("error marshaling response: %v", err)
	}

	return mcp.NewToolResultText(string(jsonResp)), nil
}

type MCPServer struct {
	server *server.MCPServer
}

func NewMCPServer() *MCPServer {
	mcpServer := server.NewMCPServer(
		"example-server",
		"1.0.0",
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
		server.WithToolCapabilities(true),
	)

	// Add the authenticated request tool
	mcpServer.AddTool(mcp.NewTool("make_authenticated_request",
		mcp.WithDescription("Makes an authenticated request"),
		mcp.WithString("message",
			mcp.Description("Message to echo"),
			mcp.Required(),
		),
	), handleMakeAuthenticatedRequestTool)

	return &MCPServer{
		server: mcpServer,
	}
}

func (s *MCPServer) ServeSSE(addr string) error {
	log.Printf("Initializing SSE server on %s", addr)

	sseServer := server.NewSSEServer(s.server,
		server.WithBaseURL(fmt.Sprintf("http://%s", addr)),
		server.WithSSEContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			log.Printf("New SSE connection from %s, headers: %v", r.RemoteAddr, r.Header)
			// Add CORS headers
			w, ok := r.Context().Value("responseWriter").(http.ResponseWriter)
			if ok {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			}
			return authFromRequest(ctx, r)
		}),
	)

	// Create a new HTTP server mux
	mux := http.NewServeMux()

	// Add test endpoint
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Test endpoint hit from %s", r.RemoteAddr)
		w.Write([]byte("Server is running"))
	})

	// Add message endpoint handler
	handleMessage := func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Handling message request")
		// Log request body for debugging
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading request body: %v", err)
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			return
		}
		log.Printf("Request body: %s", string(body))
		r.Body = io.NopCloser(bytes.NewReader(body))

		// Ensure it's a POST request
		if r.Method != "POST" {
			log.Printf("Invalid method: %s", r.Method)
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Log session ID
		sessionId := r.URL.Query().Get("sessionId")
		log.Printf("Session ID: %s", sessionId)
		if sessionId == "" {
			log.Printf("Missing session ID")
			http.Error(w, "Missing sessionId", http.StatusBadRequest)
			return
		}

		// Parse the request body
		var requestData map[string]interface{}
		if err := json.Unmarshal(body, &requestData); err != nil {
			log.Printf("Error parsing request body: %v", err)
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		log.Printf("Parsed request data: %+v", requestData)

		// Add CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle the message
		sseServer.MessageHandler().ServeHTTP(w, r)
	}

	// Add message endpoint
	mux.HandleFunc("/message", handleMessage)

	// Add SSE and message endpoints with proper path handling
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Incoming request: %s %s", r.Method, r.URL.Path)
		log.Printf("Headers: %v", r.Header)
		log.Printf("Query params: %v", r.URL.Query())

		// Extract tenant from path
		pathParts := strings.Split(r.URL.Path, "/")
		if len(pathParts) < 4 {
			log.Printf("Invalid path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}

		tenant := pathParts[2]
		endpoint := pathParts[3]
		log.Printf("Tenant: %s, Endpoint: %s", tenant, endpoint)

		// Add CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			log.Printf("Handling OPTIONS request")
			w.WriteHeader(http.StatusOK)
			return
		}

		// Route to appropriate handler
		switch endpoint {
		case "sse":
			log.Printf("Handling SSE request")
			sseServer.SSEHandler().ServeHTTP(w, r)
		case "message":
			handleMessage(w, r)
		default:
			log.Printf("Unknown endpoint: %s", endpoint)
			http.NotFound(w, r)
		}
	})

	// Add a catch-all handler for debugging
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Catch-all handler: %s %s", r.Method, r.URL.Path)
		log.Printf("Headers: %v", r.Header)
		log.Printf("Query params: %v", r.URL.Query())
		http.NotFound(w, r)
	})

	// Start the server
	log.Printf("HTTP server listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func (s *MCPServer) ServeStdio() error {
	log.Println("Starting stdio server...")
	return server.ServeStdio(s.server, server.WithStdioContextFunc(authFromEnv))
}

func main() {
	var transport = "sse"
	var addr = ":8080"
	flag.StringVar(&transport, "t", "stdio", "Transport type (stdio or sse)")
	flag.StringVar(&transport, "transport", "stdio", "Transport type (stdio or sse)")
	flag.StringVar(&addr, "addr", ":8080", "Address to listen on")
	flag.Parse()

	log.Printf("Starting server with transport: %s, address: %s", transport, addr)

	s := NewMCPServer()

	switch transport {
	case "stdio":
		if err := s.ServeStdio(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	case "sse":
		if err := s.ServeSSE(addr); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	default:
		log.Fatalf("Invalid transport type: %s. Must be 'stdio' or 'sse'", transport)
	}
}
