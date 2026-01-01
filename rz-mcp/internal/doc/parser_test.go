package doc

import (
	"testing"
)

func TestParser_ParseCommands(t *testing.T) {
	parser := NewParser()

	testInput := `Usage: [.][times][cmd][~grep][@[@iter]addr][|>pipe] ; ...
│![!]                   # Run given commands as in system(3) or shows command history
│#!<interpreter-name> [<arg1> <arg2> ...] # Run interpreter
│$[*?]                  # Alias commands and strings
│%[?]                   # Math commands
│&[jt=b-&?]             # Manage tasks
│([*-?]                 # Manage scripting macros
│*<addr>[=<expr>|<hexstring>] # Pointer read/write data/values
│.[.-*(?]               # Interpret commands
│/<?>                   # Search for bytes, regexps, patterns, ..
│:[?]                   # Command specifiers (table-output only for now)
│< <characters>         # Push escaped string into the RzCons.readChar (pressed keys) buffer
│>[?]                   # Redirection help ('>')
│?*[j] [<search_cmd>]   # Search help
│@[?]                   # '@' help, temporary modifiers, applied left-to-right
│@@[?]                  # '@@' help, iterators
│_                      # Print last output
│a<?>                   # Analysis commands
│B[jqt] [<pointer_bits>] # Computes the possibles firmware locations in memory a.k.a basefind (CPU intensive)
│b[j*-+fm]              # Display or change the block size
│c[?]                   # Compare block with given data
│C[?]                   # Code metadata (comments, format, hints, ..)
│d<?>                   # Debugger commands
│dex<se>                # Core plugin to visualize dex class information`

	commands := parser.ParseCommands(testInput)

	// Test that we got some commands
	if len(commands) == 0 {
		t.Fatal("Expected to parse some commands, got 0")
	}

	// Test specific command parsing
	expectedCommands := map[string]string{
		"!":   "Run given commands as in system(3) or shows command history",
		"$":   "Alias commands and strings",
		"%":   "Math commands",
		"a":   "Analysis commands",
		"b":   "Display or change the block size",
		"c":   "Compare block with given data",
		"C":   "Code metadata (comments, format, hints, ..)",
		"d":   "Debugger commands",
		"dex": "Core plugin to visualize dex class information",
	}

	foundCommands := make(map[string]Command)
	for _, cmd := range commands {
		foundCommands[cmd.Name] = cmd
	}

	for expectedName, expectedDesc := range expectedCommands {
		cmd, found := foundCommands[expectedName]
		if !found {
			t.Errorf("Expected command '%s' not found", expectedName)
			continue
		}
		if cmd.Description != expectedDesc {
			t.Errorf("Command '%s': expected description '%s', got '%s'", expectedName, expectedDesc, cmd.Description)
		}
	}
}

func TestParser_cleanCommandName(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		input    string
		expected string
	}{
		{"a<?>" , "a"},
		{"[!]", "!"},
		{"B[jqt]", "Bjqt"},
		{"*<addr>", "*addr"},
		{"?*[j]", "*j"},
		{"simple", "simple"},
		{"", ""},
	}

	for _, test := range tests {
		result := parser.cleanCommandName(test.input)
		if result != test.expected {
			t.Errorf("cleanCommandName(%q): expected %q, got %q", test.input, test.expected, result)
		}
	}
}

func TestParser_categorizeCommand(t *testing.T) {
	parser := NewParser()

	tests := []struct {
		input            string
		expectedFamily   string
		expectedSubcmd   string
	}{
		{"a", "a", "a"},
		{"ab", "a", "b"},
		{"abc", "a", "bc"},
		{"dex", "d", "ex"},
		{"!", "special", "!"},
		{"@", "special", "@"},
		{"/", "special", "special"},
		{"a/b", "a", "bSLASH"},  // Test SLASH replacement
		{"", "misc", "misc"},
	}

	for _, test := range tests {
		family, subcommand := parser.categorizeCommand(test.input)
		if family != test.expectedFamily {
			t.Errorf("categorizeCommand(%q): expected family %q, got %q", test.input, test.expectedFamily, family)
		}
		if subcommand != test.expectedSubcmd {
			t.Errorf("categorizeCommand(%q): expected subcommand %q, got %q", test.input, test.expectedSubcmd, subcommand)
		}
	}
}