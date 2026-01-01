package server

import (
	"encoding/json"
	"testing"
)

func TestServerInitialization(t *testing.T) {
	server := New()
	defer server.Close()

	if server == nil {
		t.Fatal("Expected server to be created, got nil")
	}
}

func TestInitializeRequest(t *testing.T) {
	server := New()
	defer server.Close()

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "test-client",
				"version": "1.0",
			},
		},
	}

	response := server.HandleRequest(req)

	// Verify response structure
	if response.JSONRPC != "2.0" {
		t.Errorf("Expected JSONRPC '2.0', got '%s'", response.JSONRPC)
	}

	if response.ID != 1 {
		t.Errorf("Expected ID 1, got %v", response.ID)
	}

	if response.Error != nil {
		t.Errorf("Expected no error, got %v", response.Error)
	}

	if response.Result == nil {
		t.Fatal("Expected result, got nil")
	}

	// Verify initialize result structure
	result := response.Result.(map[string]interface{})
	if result["protocolVersion"] != "2024-11-05" {
		t.Errorf("Expected protocolVersion '2024-11-05', got %v", result["protocolVersion"])
	}

	capabilities, ok := result["capabilities"].(map[string]interface{})
	if !ok {
		t.Error("Expected capabilities to be a map")
	}

	if capabilities["tools"] == nil {
		t.Error("Expected tools capability to be present")
	}

	serverInfo, ok := result["serverInfo"].(map[string]interface{})
	if !ok {
		t.Error("Expected serverInfo to be a map")
	}

	if serverInfo["name"] != "rizin-mcp-server" {
		t.Errorf("Expected server name 'rizin-mcp-server', got %v", serverInfo["name"])
	}
}

func TestToolsList(t *testing.T) {
	server := New()
	defer server.Close()

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
		Params:  map[string]interface{}{},
	}

	response := server.HandleRequest(req)

	if response.Error != nil {
		t.Errorf("Expected no error, got %v", response.Error)
	}

	if response.Result == nil {
		t.Fatal("Expected result, got nil")
	}

	result := response.Result.(map[string]interface{})
	tools, ok := result["tools"].([]Tool)
	if !ok {
		t.Fatal("Expected tools to be a []Tool")
	}

	// Verify we have the expected tools
	expectedTools := map[string]bool{
		"analyze_file":          false,
		"open_file":             false,
		"close_file":            false,
		"disassemble":           false,
		"print_hex":             false,
		"get_info":              false,
		"seek":                  false,
		"analyze_function":      false,
		"find_strings":          false,
		"execute_command":       false,
		"get_executable_info":   false,
		"get_entrypoints":       false,
		"get_exported_symbols":  false,
		"get_imported_symbols":  false,
		"get_all_symbols":       false,
		"get_segments":          false,
		"get_sections":          false,
		"get_strings_detailed":  false,
	}

	for _, tool := range tools {
		if _, exists := expectedTools[tool.Name]; exists {
			expectedTools[tool.Name] = true
		}

		// Verify each tool has required fields
		if tool.Name == "" {
			t.Error("Tool name should not be empty")
		}
		if tool.Description == "" {
			t.Error("Tool description should not be empty")
		}
		if tool.InputSchema == nil {
			t.Error("Tool input schema should not be nil")
		}
	}

	// Check that all expected tools were found
	for toolName, found := range expectedTools {
		if !found {
			t.Errorf("Expected tool '%s' not found in tools list", toolName)
		}
	}
}

func TestInvalidMethod(t *testing.T) {
	server := New()
	defer server.Close()

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "invalid/method",
		Params:  map[string]interface{}{},
	}

	response := server.HandleRequest(req)

	if response.Error == nil {
		t.Error("Expected error for invalid method, got nil")
	}

	if response.Error.Code != -32601 {
		t.Errorf("Expected error code -32601, got %d", response.Error.Code)
	}

	if response.Error.Message != "Method not found" {
		t.Errorf("Expected error message 'Method not found', got '%s'", response.Error.Message)
	}
}

func TestToolCallWithoutRizin(t *testing.T) {
	server := New()
	defer server.Close()

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "get_executable_info",
			"arguments": map[string]interface{}{},
		},
	}

	response := server.HandleRequest(req)

	if response.Error == nil {
		t.Error("Expected error when no file is loaded, got nil")
	}

	if response.Error.Message != "No file loaded. Use open_file first" {
		t.Errorf("Expected 'No file loaded' error, got '%s'", response.Error.Message)
	}
}

func TestCloseFileWithoutRizin(t *testing.T) {
	server := New()
	defer server.Close()

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "close_file",
			"arguments": map[string]interface{}{},
		},
	}

	response := server.HandleRequest(req)

	if response.Error == nil {
		t.Error("Expected error when no rizin session is active, got nil")
	}

	if response.Error.Message != "No rizin session active" {
		t.Errorf("Expected 'No rizin session active' error, got '%s'", response.Error.Message)
	}
}

func TestInvalidToolCall(t *testing.T) {
	server := New()
	defer server.Close()

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      6,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "nonexistent_tool",
			"arguments": map[string]interface{}{},
		},
	}

	response := server.HandleRequest(req)

	if response.Error == nil {
		t.Error("Expected error for nonexistent tool, got nil")
	}

	if response.Error.Code != -32601 {
		t.Errorf("Expected error code -32601, got %d", response.Error.Code)
	}

	if response.Error.Message != "Tool not found" {
		t.Errorf("Expected error message 'Tool not found', got '%s'", response.Error.Message)
	}
}

func TestJSONMarshaling(t *testing.T) {
	server := New()
	defer server.Close()

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      7,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "test-client",
				"version": "1.0",
			},
		},
	}

	response := server.HandleRequest(req)

	// Test that response can be marshaled to JSON
	_, err := json.Marshal(response)
	if err != nil {
		t.Errorf("Failed to marshal response to JSON: %v", err)
	}
}

func TestMCPRequestParsing(t *testing.T) {
	jsonRequest := `{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "initialize",
		"params": {
			"protocolVersion": "2024-11-05",
			"capabilities": {},
			"clientInfo": {
				"name": "test-client",
				"version": "1.0"
			}
		}
	}`

	var req MCPRequest
	err := json.Unmarshal([]byte(jsonRequest), &req)
	if err != nil {
		t.Fatalf("Failed to unmarshal JSON request: %v", err)
	}

	if req.JSONRPC != "2.0" {
		t.Errorf("Expected JSONRPC '2.0', got '%s'", req.JSONRPC)
	}

	if req.ID != float64(1) { // JSON unmarshals numbers as float64
		t.Errorf("Expected ID 1, got %v", req.ID)
	}

	if req.Method != "initialize" {
		t.Errorf("Expected method 'initialize', got '%s'", req.Method)
	}

	if req.Params == nil {
		t.Error("Expected params to be present")
	}
}

// Benchmark tests
func BenchmarkInitializeRequest(b *testing.B) {
	server := New()
	defer server.Close()

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "test-client",
				"version": "1.0",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.HandleRequest(req)
	}
}

func BenchmarkToolsList(b *testing.B) {
	server := New()
	defer server.Close()

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
		Params:  map[string]interface{}{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server.HandleRequest(req)
	}
}