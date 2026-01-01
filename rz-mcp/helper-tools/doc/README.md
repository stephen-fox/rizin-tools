# Rizin Documentation Generator

This Go program uses the radareutil library to extract rizin commands and generate a structured documentation file tree.

## Usage

```bash
go run main.go -output /path/to/output/directory
```

## Architecture

The program is split into two main components:

- **`main.go`**: CLI interface and orchestration
- **`internal/doc`**: Core parsing and generation logic

### Internal Package Structure

- **`internal/doc/parser.go`**: Handles parsing of rizin help output
- **`internal/doc/generator.go`**: Manages documentation file generation
- **`internal/doc/parser_test.go`**: Tests for parsing functionality
- **`internal/doc/generator_test.go`**: Tests for generation functionality

## Features

- Extracts all rizin commands and their descriptions using the `?` command
- Groups commands by family (first letter of command)
- Creates subdirectories for each command family
- Generates markdown files for each subcommand within a family
- Handles special characters by substituting "/" with "SLASH" in filenames
- Includes detailed help for command families when available

## Testing

Run tests for the internal doc package:

```bash
go test ./internal/doc
```

## Output Structure

```
output_directory/
├── a/
│   ├── a.md
│   ├── aa.md
│   └── af.md
├── d/
│   ├── d.md
│   └── db.md
├── p/
│   ├── p.md
│   ├── px.md
│   └── pdf.md
└── special/
    ├── _.md
    └── !.md
```

Each markdown file contains:
- Command table with names and descriptions
- Detailed help output for the command family (when available)