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
- [rz-paths](rz-paths) - rz-paths finds code paths between a child symbol
  and a parent symbol using rizin
- [vstack](vstack) - vstack visualizes the stack variables of a function
  based on rizin's afi output, supporting only 64-bit programs.
