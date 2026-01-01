package server

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/stephen-fox/radareutil"
)

type Server struct {
	rizinAPI radareutil.Api
}

func New() *Server {
	return &Server{}
}

func (s *Server) initializeRizin(target, arch, bits string) error {
	config := &radareutil.Radare2Config{
		ExecutablePath: "rizin",
	}

	var args []string

	// Add architecture if specified
	if arch != "" {
		args = append(args, "-a", arch)
	}

	// Add bits if specified
	if bits != "" {
		args = append(args, "-b", bits)
	}

	// Add target file if specified
	if target != "" {
		args = append(args, target)
	}

	if len(args) > 0 {
		config.AdditionalCliArgs = args
	}

	var err error
	s.rizinAPI, err = radareutil.NewCliApi(config)
	if err != nil {
		return fmt.Errorf("failed to create rizin CLI API: %w", err)
	}

	err = s.rizinAPI.Start()
	if err != nil {
		return fmt.Errorf("failed to start rizin: %w", err)
	}

	return nil
}

func (s *Server) HandleRequest(req MCPRequest) MCPResponse {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolCall(req)
	default:
		return MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &MCPError{
				Code:    -32601,
				Message: "Method not found",
			},
		}
	}
}

func (s *Server) handleInitialize(req MCPRequest) MCPResponse {
	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: InitializeResult{
			ProtocolVersion: "2024-11-05",
			Capabilities: map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			ServerInfo: struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}{
				Name:    "rizin-mcp-server",
				Version: "1.0.0",
			},
		},
	}
}

func (s *Server) handleToolsList(req MCPRequest) MCPResponse {
	tools := []Tool{
		{
			Name:        "open_file",
			Description: "Open a file in rizin using command-line arguments and run analysis",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the binary file to open",
					},
					"architecture": map[string]interface{}{
						"type":        "string",
						"description": "CPU architecture (e.g., x86, arm, mips) - optional",
					},
					"bits": map[string]interface{}{
						"type":        "string",
						"description": "CPU bits (e.g., 16, 32, 64) - optional",
					},
				},
				"required": []string{"file_path"},
			},
		},
		{
			Name:        "close_file",
			Description: "Close the currently opened file in rizin using 'o--' command",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "disassemble",
			Description: "Disassemble code at a specific address",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"address": map[string]interface{}{
						"type":        "string",
						"description": "Address to disassemble (hex format)",
					},
					"count": map[string]interface{}{
						"type":        "integer",
						"description": "Number of instructions to disassemble",
						"default":     10,
					},
				},
				"required": []string{"address"},
			},
		},
		{
			Name:        "print_hex",
			Description: "Print hexadecimal dump at a specific address",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"address": map[string]interface{}{
						"type":        "string",
						"description": "Address to print (hex format)",
					},
					"size": map[string]interface{}{
						"type":        "integer",
						"description": "Number of bytes to print",
						"default":     64,
					},
				},
				"required": []string{"address"},
			},
		},
		{
			Name:        "get_info",
			Description: "Get basic information about the loaded binary",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "seek",
			Description: "Seek to a specific address",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"address": map[string]interface{}{
						"type":        "string",
						"description": "Address to seek to (hex format)",
					},
				},
				"required": []string{"address"},
			},
		},
		{
			Name:        "analyze_function",
			Description: "Analyze functions in the binary",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"address": map[string]interface{}{
						"type":        "string",
						"description": "Address of function to analyze (optional)",
					},
				},
			},
		},
		{
			Name:        "find_strings",
			Description: "Find strings in the binary",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"min_length": map[string]interface{}{
						"type":        "integer",
						"description": "Minimum string length",
						"default":     4,
					},
				},
			},
		},
		{
			Name:        "execute_command",
			Description: "Execute a raw rizin command",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"command": map[string]interface{}{
						"type":        "string",
						"description": "Rizin command to execute",
					},
				},
				"required": []string{"command"},
			},
		},
		{
			Name:        "get_executable_info",
			Description: "Get detailed executable information (architecture, OS, etc.)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "get_entrypoints",
			Description: "Get executable entrypoints",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "get_exported_symbols",
			Description: "Get exported symbols (public functions and variables)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "get_imported_symbols",
			Description: "Get imported symbols from other libraries",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "get_all_symbols",
			Description: "Get all symbols (exports, imports, local functions)",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "get_segments",
			Description: "Get executable segments",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "get_sections",
			Description: "Get executable sections",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "get_strings_detailed",
			Description: "Get all strings in the executable with detailed information",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{},
			},
		},
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	}
}

func (s *Server) handleToolCall(req MCPRequest) MCPResponse {
	var params ToolCallParams
	paramBytes, err := json.Marshal(req.Params)
	if err != nil {
		return MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &MCPError{
				Code:    -32602,
				Message: "Invalid params",
			},
		}
	}

	err = json.Unmarshal(paramBytes, &params)
	if err != nil {
		return MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &MCPError{
				Code:    -32602,
				Message: "Invalid params format",
			},
		}
	}

	switch params.Name {
	case "open_file":
		return s.handleOpenFile(req, params)
	case "close_file":
		return s.handleCloseFile(req, params)
	case "disassemble":
		return s.handleDisassemble(req, params)
	case "print_hex":
		return s.handlePrintHex(req, params)
	case "get_info":
		return s.handleGetInfo(req, params)
	case "seek":
		return s.handleSeek(req, params)
	case "analyze_function":
		return s.handleAnalyzeFunction(req, params)
	case "find_strings":
		return s.handleFindStrings(req, params)
	case "execute_command":
		return s.handleExecuteCommand(req, params)
	case "get_executable_info":
		return s.handleGetExecutableInfo(req, params)
	case "get_entrypoints":
		return s.handleGetEntrypoints(req, params)
	case "get_exported_symbols":
		return s.handleGetExportedSymbols(req, params)
	case "get_imported_symbols":
		return s.handleGetImportedSymbols(req, params)
	case "get_all_symbols":
		return s.handleGetAllSymbols(req, params)
	case "get_segments":
		return s.handleGetSegments(req, params)
	case "get_sections":
		return s.handleGetSections(req, params)
	case "get_strings_detailed":
		return s.handleGetStringsDetailed(req, params)
	default:
		return MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &MCPError{
				Code:    -32601,
				Message: "Tool not found",
			},
		}
	}
}


func (s *Server) handleDisassemble(req MCPRequest, params ToolCallParams) MCPResponse {
	address, ok := params.Arguments["address"].(string)
	if !ok {
		return s.errorResponse(req.ID, "address parameter required")
	}

	count := 10
	if c, ok := params.Arguments["count"].(float64); ok {
		count = int(c)
	}

	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use analyze_file first")
	}

	_, err := s.rizinAPI.Execute(fmt.Sprintf("s %s", address))
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to seek to address: %v", err))
	}

	disasm, err := s.rizinAPI.Execute(fmt.Sprintf("pd %d", count))
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to disassemble: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Disassembly at %s (%d instructions):\n%s", address, count, disasm),
				},
			},
		},
	}
}

func (s *Server) handlePrintHex(req MCPRequest, params ToolCallParams) MCPResponse {
	address, ok := params.Arguments["address"].(string)
	if !ok {
		return s.errorResponse(req.ID, "address parameter required")
	}

	size := 64
	if sz, ok := params.Arguments["size"].(float64); ok {
		size = int(sz)
	}

	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use analyze_file first")
	}

	_, err := s.rizinAPI.Execute(fmt.Sprintf("s %s", address))
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to seek to address: %v", err))
	}

	hexdump, err := s.rizinAPI.Execute(fmt.Sprintf("px %d", size))
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to print hex: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Hex dump at %s (%d bytes):\n%s", address, size, hexdump),
				},
			},
		},
	}
}

func (s *Server) handleGetInfo(req MCPRequest, params ToolCallParams) MCPResponse {
	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use analyze_file first")
	}

	info, err := s.rizinAPI.Execute("i")
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to get info: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Binary Information:\n%s", info),
				},
			},
		},
	}
}

func (s *Server) handleSeek(req MCPRequest, params ToolCallParams) MCPResponse {
	address, ok := params.Arguments["address"].(string)
	if !ok {
		return s.errorResponse(req.ID, "address parameter required")
	}

	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use analyze_file first")
	}

	result, err := s.rizinAPI.Execute(fmt.Sprintf("s %s", address))
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to seek: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Seeked to address %s\n%s", address, result),
				},
			},
		},
	}
}

func (s *Server) handleAnalyzeFunction(req MCPRequest, params ToolCallParams) MCPResponse {
	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use analyze_file first")
	}

	var cmd string
	if address, ok := params.Arguments["address"].(string); ok {
		cmd = fmt.Sprintf("af @ %s; pdf @ %s", address, address)
	} else {
		cmd = "afl"
	}

	result, err := s.rizinAPI.Execute(cmd)
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to analyze function: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Function Analysis:\n%s", result),
				},
			},
		},
	}
}

func (s *Server) handleFindStrings(req MCPRequest, params ToolCallParams) MCPResponse {
	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use analyze_file first")
	}

	minLength := 4
	if ml, ok := params.Arguments["min_length"].(float64); ok {
		minLength = int(ml)
	}

	cmd := fmt.Sprintf("izz~ZSTR[1,%d,99]", minLength)
	result, err := s.rizinAPI.Execute(cmd)
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to find strings: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Strings (min length %d):\n%s", minLength, result),
				},
			},
		},
	}
}

func (s *Server) handleExecuteCommand(req MCPRequest, params ToolCallParams) MCPResponse {
	command, ok := params.Arguments["command"].(string)
	if !ok {
		return s.errorResponse(req.ID, "command parameter required")
	}

	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use analyze_file first")
	}

	result, err := s.rizinAPI.Execute(command)
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to execute command: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Command: %s\nResult:\n%s", command, result),
				},
			},
		},
	}
}

func (s *Server) errorResponse(id interface{}, message string) MCPResponse {
	return MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &MCPError{
			Code:    -32000,
			Message: message,
		},
	}
}

func (s *Server) handleOpenFile(req MCPRequest, params ToolCallParams) MCPResponse {
	filePath, ok := params.Arguments["file_path"].(string)
	if !ok {
		return s.errorResponse(req.ID, "file_path parameter required")
	}

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Invalid file path: %v", err))
	}

	// Extract optional architecture parameter
	var arch string
	if archValue, exists := params.Arguments["architecture"]; exists {
		if archStr, ok := archValue.(string); ok {
			arch = archStr
		}
	}

	// Extract optional bits parameter
	var bits string
	if bitsValue, exists := params.Arguments["bits"]; exists {
		if bitsStr, ok := bitsValue.(string); ok {
			bits = bitsStr
		}
	}

	// Kill any existing rizin session
	if s.rizinAPI != nil {
		s.rizinAPI.Kill()
		s.rizinAPI = nil
	}

	// Initialize rizin with the file and optional architecture/bits as command-line arguments
	err = s.initializeRizin(absPath, arch, bits)
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to initialize rizin with file: %v", err))
	}

	// Run analysis
	analysisResult, err := s.rizinAPI.Execute("aaa")
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to analyze file: %v", err))
	}

	// Get file info
	info, err := s.rizinAPI.Execute("i")
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to get file info: %v", err))
	}

	// Build response text with architecture info if specified
	responseText := fmt.Sprintf("File opened successfully: %s", filePath)
	if arch != "" || bits != "" {
		responseText += "\nArchitecture settings:"
		if arch != "" {
			responseText += fmt.Sprintf("\n  Architecture: %s", arch)
		}
		if bits != "" {
			responseText += fmt.Sprintf("\n  Bits: %s", bits)
		}
	}
	responseText += fmt.Sprintf("\n\nAnalysis Complete:\n%s\n\nFile Info:\n%s", analysisResult, info)

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": responseText,
				},
			},
		},
	}
}

func (s *Server) handleCloseFile(req MCPRequest, params ToolCallParams) MCPResponse {
	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No rizin session active")
	}

	// Kill the rizin process completely to avoid issues with reopening files
	s.rizinAPI.Kill()
	s.rizinAPI = nil

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": "File closed successfully and rizin process killed.",
				},
			},
		},
	}
}

func (s *Server) handleGetExecutableInfo(req MCPRequest, params ToolCallParams) MCPResponse {
	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use open_file first")
	}

	// Use the ctxkit command: "iIj" for detailed executable info
	result, err := s.rizinAPI.Execute("iIj")
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to get executable info: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Executable Information (JSON):\n%s", result),
				},
			},
		},
	}
}

func (s *Server) handleGetEntrypoints(req MCPRequest, params ToolCallParams) MCPResponse {
	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use open_file first")
	}

	// Use the ctxkit command: "ie" for entrypoints
	result, err := s.rizinAPI.Execute("iej")
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to get entrypoints: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Entrypoints (JSON):\n%s", result),
				},
			},
		},
	}
}

func (s *Server) handleGetExportedSymbols(req MCPRequest, params ToolCallParams) MCPResponse {
	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use open_file first")
	}

	// Use the ctxkit command: "iEj" for exported symbols
	result, err := s.rizinAPI.Execute("iEj")
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to get exported symbols: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Exported Symbols (JSON):\n%s", result),
				},
			},
		},
	}
}

func (s *Server) handleGetImportedSymbols(req MCPRequest, params ToolCallParams) MCPResponse {
	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use open_file first")
	}

	// Use the ctxkit command: "iij" for imported symbols
	result, err := s.rizinAPI.Execute("iij")
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to get imported symbols: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Imported Symbols (JSON):\n%s", result),
				},
			},
		},
	}
}

func (s *Server) handleGetAllSymbols(req MCPRequest, params ToolCallParams) MCPResponse {
	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use open_file first")
	}

	// Use the ctxkit command: "isj" for all symbols
	result, err := s.rizinAPI.Execute("isj")
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to get all symbols: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("All Symbols (JSON):\n%s", result),
				},
			},
		},
	}
}

func (s *Server) handleGetSegments(req MCPRequest, params ToolCallParams) MCPResponse {
	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use open_file first")
	}

	// Use the ctxkit command: "iSSj" for segments
	result, err := s.rizinAPI.Execute("iSSj")
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to get segments: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Executable Segments (JSON):\n%s", result),
				},
			},
		},
	}
}

func (s *Server) handleGetSections(req MCPRequest, params ToolCallParams) MCPResponse {
	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use open_file first")
	}

	// Use the ctxkit command: "iSj" for sections
	result, err := s.rizinAPI.Execute("iSj")
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to get sections: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Executable Sections (JSON):\n%s", result),
				},
			},
		},
	}
}

func (s *Server) handleGetStringsDetailed(req MCPRequest, params ToolCallParams) MCPResponse {
	if s.rizinAPI == nil {
		return s.errorResponse(req.ID, "No file loaded. Use open_file first")
	}

	// Use the ctxkit command: "izzj" for detailed strings
	result, err := s.rizinAPI.Execute("izzj")
	if err != nil {
		return s.errorResponse(req.ID, fmt.Sprintf("Failed to get detailed strings: %v", err))
	}

	return MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Detailed Strings (JSON):\n%s", result),
				},
			},
		},
	}
}

func (s *Server) Close() {
	if s.rizinAPI != nil {
		s.rizinAPI.Kill()
	}
}