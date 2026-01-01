package doc

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/stephen-fox/radareutil"
)

// Command represents a rizin command with its metadata
type Command struct {
	Name        string
	Description string
	Family      string
	Subcommand  string
}

// Parser handles parsing of rizin help output
type Parser struct {
	cmdRegex *regexp.Regexp
}

// NewParser creates a new parser for rizin help output
func NewParser() *Parser {
	// Regex to match rizin command lines with Unicode box characters
	// Format: │<command> <spaces> # <description>
	cmdRegex := regexp.MustCompile(`^[│]\s*([^\s#]+)(?:\s+.*?)?\s+#\s+(.+)$`)

	return &Parser{
		cmdRegex: cmdRegex,
	}
}

// ParseCommands extracts commands from rizin help output
func (p *Parser) ParseCommands(helpOutput string) []Command {
	var commands []Command
	scanner := bufio.NewScanner(strings.NewReader(helpOutput))

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "Usage:") || strings.HasPrefix(line, "Examples:") {
			continue
		}

		matches := p.cmdRegex.FindStringSubmatch(line)
		if len(matches) == 3 {
			cmdName := strings.TrimSpace(matches[1])
			description := strings.TrimSpace(matches[2])

			// Clean up command name - remove angle brackets and optional indicators
			cmdName = p.cleanCommandName(cmdName)

			if cmdName != "" && description != "" && !strings.Contains(cmdName, " ") {
				family, subcommand := p.categorizeCommand(cmdName)
				commands = append(commands, Command{
					Name:        cmdName,
					Description: description,
					Family:      family,
					Subcommand:  subcommand,
				})
			}
		}
	}

	return commands
}

// cleanCommandName removes formatting characters from command names
func (p *Parser) cleanCommandName(cmdName string) string {
	cmdName = strings.TrimSuffix(strings.TrimPrefix(cmdName, "<"), ">")
	cmdName = strings.ReplaceAll(cmdName, "[", "")
	cmdName = strings.ReplaceAll(cmdName, "]", "")
	cmdName = strings.ReplaceAll(cmdName, "?", "")
	return cmdName
}

// categorizeCommand determines the family and subcommand for a given command
func (p *Parser) categorizeCommand(cmdName string) (family, subcommand string) {
	// Handle special cases and get family (first character)
	if len(cmdName) == 0 {
		return "misc", "misc"
	}

	family = string(cmdName[0])

	// Handle special characters that might not be valid for directory names
	switch family {
	case "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "=", "[", "]", "{", "}", "|", "\\", ":", ";", "'", "\"", "<", ">", "?", ",", ".", "/":
		family = "special"
	}

	// Get subcommand (everything after first character, or use the full command if single char)
	if len(cmdName) > 1 {
		subcommand = cmdName[1:]
		// Replace '/' with 'SLASH' as specified
		subcommand = strings.ReplaceAll(subcommand, "/", "SLASH")
	} else {
		subcommand = cmdName
	}

	// If subcommand is empty, use the family name
	if subcommand == "" {
		subcommand = family
	}

	return family, subcommand
}

// GetDetailedHelp gets detailed help for a command family using rizin API
func GetDetailedHelp(cliApi radareutil.Api, family string) (string, error) {
	helpCmd := family + "?"
	detailHelp, err := cliApi.Execute(helpCmd)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(detailHelp), nil
}