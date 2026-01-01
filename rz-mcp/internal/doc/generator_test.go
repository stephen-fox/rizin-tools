package doc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with/slash", "withSLASHslash"},
		{"with\\backslash", "withBACKSLASHbackslash"},
		{"with:colon", "withCOLONcolon"},
		{"with*star", "withSTARstar"},
		{"with?question", "withQUESTIONquestion"},
		{"with\"quote", "withQUOTEquote"},
		{"with<lt>gt", "withLTltGTgt"},
		{"with|pipe", "withPIPEpipe"},
		{"!special", "_!special"},
		{"@special", "_@special"},
		{"123number", "_123number"},
		{"", ""},
	}

	for _, test := range tests {
		result := SanitizeFilename(test.input)
		if result != test.expected {
			t.Errorf("SanitizeFilename(%q): expected %q, got %q", test.input, test.expected, result)
		}
	}
}

func TestGenerator_GenerateDocs(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "doc_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	generator := NewGenerator(tempDir)

	// Test commands
	commands := []Command{
		{Name: "a", Description: "Analysis commands", Family: "a", Subcommand: "a"},
		{Name: "ab", Description: "Analysis blocks", Family: "a", Subcommand: "b"},
		{Name: "p", Description: "Print commands", Family: "p", Subcommand: "p"},
		{Name: "px", Description: "Print hexdump", Family: "p", Subcommand: "x"},
		{Name: "!", Description: "System command", Family: "special", Subcommand: "!"},
	}

	// Mock rizin API (we'll pass nil since we're not testing the detailed help functionality)
	err = generator.GenerateDocs(commands, nil)
	if err != nil {
		t.Fatalf("GenerateDocs failed: %v", err)
	}

	// Check that directories were created
	expectedDirs := []string{"a", "p", "special"}
	for _, dir := range expectedDirs {
		dirPath := filepath.Join(tempDir, dir)
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			t.Errorf("Expected directory %s was not created", dirPath)
		}
	}

	// Check that markdown files were created
	expectedFiles := map[string][]string{
		"a":       {"a.md", "b.md"},
		"p":       {"p.md", "x.md"},
		"special": {"_!.md"},
	}

	for dir, files := range expectedFiles {
		for _, file := range files {
			filePath := filepath.Join(tempDir, dir, file)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				t.Errorf("Expected file %s was not created", filePath)
			}
		}
	}

	// Check content of one file
	aFilePath := filepath.Join(tempDir, "a", "a.md")
	content, err := os.ReadFile(aFilePath)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	contentStr := string(content)
	expectedContent := []string{
		"# a Commands",
		"| Command | Description |",
		"| `a` | Analysis commands |",
	}

	for _, expected := range expectedContent {
		if !contains(contentStr, expected) {
			t.Errorf("File content missing expected text: %s", expected)
		}
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
		 containsAt(s, substr, 1)))
}

func containsAt(s, substr string, start int) bool {
	if start >= len(s) {
		return false
	}
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}