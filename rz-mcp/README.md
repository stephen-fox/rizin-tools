# rz-mcp

rz-mcp is a stdio-based Model Context Protocol (MCP) server for the rizin
disassembler.

This project is experimental and has no safeguards against code injection.
If an "AI" tool tries to execute a rizin command that contains shell
characters or other special rizin shell characters, then rizin *will*
interpret those characters and execute code. Users must take care to
sandbox their tooling and rz-mcp.

AI tools should use the standard MCP APIs to discover available functionality.

## Helper tools

The `helper-tools` directory contains utilities to help build and work with
the MCP server. These tools include:

- `doc` - Examines rizin's help (`?`) command output to build a hierarchy of
  markdown-based documentation in a directory. It may be useful for helping
  AI tools navigate and use rizin's commands
