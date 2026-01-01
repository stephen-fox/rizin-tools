package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/stephen-fox/radareutil"
	"codeberg.org/stephen-fox/rizin-mcp-server/internal/doc"
)

func main() {
	var outputDir string
	flag.StringVar(&outputDir, "output", "", "Output directory for generated documentation")
	flag.Parse()

	if outputDir == "" {
		log.Fatal("Output directory is required. Use -output flag.")
	}

	// Create output directory if it doesn't exist
	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Initialize rizin CLI API
	cliApi, err := radareutil.NewCliApi(&radareutil.Radare2Config{
		ExecutablePath: "rizin",
	})
	if err != nil {
		log.Fatalf("Failed to create rizin CLI API: %v", err)
	}

	err = cliApi.Start()
	if err != nil {
		log.Fatalf("Failed to start rizin: %v", err)
	}
	defer cliApi.Kill()

	// Get the help output which contains all commands
	helpOutput, err := cliApi.Execute("?")
	if err != nil {
		log.Fatalf("Failed to execute help command: %v", err)
	}

	// Parse commands and generate documentation
	parser := doc.NewParser()
	commands := parser.ParseCommands(helpOutput)

	generator := doc.NewGenerator(outputDir)
	err = generator.GenerateDocs(commands, cliApi)
	if err != nil {
		log.Fatalf("Failed to generate documentation: %v", err)
	}

	fmt.Printf("Documentation generated successfully in: %s\n", outputDir)
	fmt.Printf("Parsed %d commands into documentation.\n", len(commands))
}
