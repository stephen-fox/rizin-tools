package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"codeberg.org/stephen-fox/rizin-mcp-server/internal/server"
)

func main() {
	mcpServer := server.New()
	defer mcpServer.Close()

	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var req server.MCPRequest
		err := json.Unmarshal([]byte(line), &req)
		if err != nil {
			log.Printf("Error parsing JSON: %v", err)
			continue
		}

		response := mcpServer.HandleRequest(req)

		responseJSON, err := json.Marshal(response)
		if err != nil {
			log.Printf("Error marshaling response: %v", err)
			continue
		}

		fmt.Println(string(responseJSON))
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading stdin: %v", err)
	}
}
