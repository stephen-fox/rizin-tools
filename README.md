# rizin tools

Various tools for working with the [rizin disassembler and debugger][rizin].

[rizin]: https://rizin.re/

## Repository structure

A short summary of the tools found in this repository can be found below.
Each tool has its own dedicated directory and README. Please refer to the
tool's README for further information.

- [library-exports](library-exports) - Generates a list of a library's
  exported symbols and their signatures. Useful for developing a proxy
  library
- [rz-ctx](rz-ctx) - rz-ctx is an experimental utility that attempts
  to capture rizin's analysis in JSON objects with documented schemas
  so that analysis data can be committed to source control and be
  consumed by other tools
- [rz-mcp](rz-mcp) - An experimental MCP server for use with "AI" tools.
  Must be sandboxed due to possibility of code injection
- [rz-paths](rz-paths) - rz-paths finds code paths between a child symbol
  and a parent symbol using rizin
- [vstack](vstack) - vstack visualizes the stack variables of a function
  based on rizin's afi output, supporting only 64-bit programs.
