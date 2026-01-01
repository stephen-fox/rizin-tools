package doc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/stephen-fox/radareutil"
)

// Generator handles generation of documentation files
type Generator struct {
	outputDir string
}

// NewGenerator creates a new documentation generator
func NewGenerator(outputDir string) *Generator {
	return &Generator{
		outputDir: outputDir,
	}
}

// GenerateDocs creates the complete documentation file tree
func (g *Generator) GenerateDocs(commands []Command, cliApi radareutil.Api) error {
	// Group commands by family
	families := make(map[string][]Command)
	for _, cmd := range commands {
		families[cmd.Family] = append(families[cmd.Family], cmd)
	}

	// Create family directories and markdown files
	for family, familyCommands := range families {
		familyDir := filepath.Join(g.outputDir, family)
		err := os.MkdirAll(familyDir, 0755)
		if err != nil {
			return fmt.Errorf("failed to create family directory %s: %v", familyDir, err)
		}

		// Create markdown files for each subcommand
		subcommands := make(map[string][]Command)
		for _, cmd := range familyCommands {
			subcommands[cmd.Subcommand] = append(subcommands[cmd.Subcommand], cmd)
		}

		for subcommand, subcmdCommands := range subcommands {
			filename := SanitizeFilename(subcommand) + ".md"
			filepath := filepath.Join(familyDir, filename)

			err := g.createMarkdownFile(filepath, subcommand, subcmdCommands, cliApi)
			if err != nil {
				return fmt.Errorf("failed to create markdown file %s: %v", filepath, err)
			}
		}
	}

	return nil
}

// SanitizeFilename replaces problematic characters with safe alternatives
func SanitizeFilename(filename string) string {
	// Replace problematic characters with safe alternatives
	filename = strings.ReplaceAll(filename, "/", "SLASH")
	filename = strings.ReplaceAll(filename, "\\", "BACKSLASH")
	filename = strings.ReplaceAll(filename, ":", "COLON")
	filename = strings.ReplaceAll(filename, "*", "STAR")
	filename = strings.ReplaceAll(filename, "?", "QUESTION")
	filename = strings.ReplaceAll(filename, "\"", "QUOTE")
	filename = strings.ReplaceAll(filename, "<", "LT")
	filename = strings.ReplaceAll(filename, ">", "GT")
	filename = strings.ReplaceAll(filename, "|", "PIPE")

	// If filename starts with special characters, prefix with underscore
	if len(filename) > 0 && !((filename[0] >= 'a' && filename[0] <= 'z') || (filename[0] >= 'A' && filename[0] <= 'Z')) {
		filename = "_" + filename
	}

	return filename
}

// createMarkdownFile generates a markdown file for a subcommand
func (g *Generator) createMarkdownFile(filepath string, subcommand string, commands []Command, cliApi radareutil.Api) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write markdown header
	fmt.Fprintf(writer, "# %s Commands\n\n", subcommand)
	fmt.Fprintf(writer, "This document contains information about rizin commands in the '%s' subcommand family.\n\n", subcommand)

	// Write commands table
	fmt.Fprintf(writer, "## Commands\n\n")
	fmt.Fprintf(writer, "| Command | Description |\n")
	fmt.Fprintf(writer, "|---------|-------------|\n")

	for _, cmd := range commands {
		// Escape pipe characters in the command name and description for markdown table
		escapedName := strings.ReplaceAll(cmd.Name, "|", "\\|")
		escapedDesc := strings.ReplaceAll(cmd.Description, "|", "\\|")
		fmt.Fprintf(writer, "| `%s` | %s |\n", escapedName, escapedDesc)
	}

	// Try to get more detailed help for the subcommand family
	if len(commands) > 0 {
		firstCmd := commands[0]
		detailHelp, err := GetDetailedHelp(cliApi, firstCmd.Family)
		if err == nil && detailHelp != "" {
			fmt.Fprintf(writer, "\n## Detailed Help\n\n")
			fmt.Fprintf(writer, "```\n%s\n```\n", detailHelp)
		}
	}

	return nil
}