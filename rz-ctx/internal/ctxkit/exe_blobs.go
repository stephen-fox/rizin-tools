package ctxkit

func executableInfoCtxBlob() CtxBlob {
	return CtxBlob{
		Name:        "executable-information",
		Description: "Show binary info",
		Command:     "iIj",
		Schema: ObjectSchema{
			Fields: []FieldSchema{
				{
					Name:        "arch",
					Description: "CPU architecture",
				},
				{
					Name:        "baddr",
					Description: "Base address",
				},
				{
					Name:        "binsz",
					Description: "Binary size",
				},
				{
					Name:        "bintype",
					Description: "Executable file format",
				},
				{
					Name:        "bits",
					Description: "Pointer size in bits",
				},
				{
					Name:        "compiled",
					Description: "Compilation timestamp",
				},
				{
					Name:        "lang",
					Description: "The programming language",
				},
				{
					Name:        "machine",
					Description: "The target CPU type",
				},
				{
					Name:        "os",
					Description: "The operating system",
				},
			},
		},
	}
}

func executableEntrypointsCtxBlob() CtxBlob {
	return CtxBlob{
		Name:        "executable-entrypoints",
		Description: "Entrypoints",
		Command:     "ie",
		Schema: []ObjectSchema{
			ObjectSchema{
				Fields: []FieldSchema{
					{
						Name:        "vaddr",
						Description: "Virtual address in base 10",
					},
					{
						Name:        "paddr",
						Description: "Physical address in base 10",
					},
					{
						Name:        "baddr",
						Description: "Base address in base 10",
					},
					{
						Name:        "laddr",
						Description: "Load address in base 10",
					},
					{
						Name:        "haddr",
						Description: "Hardware address in base 10",
					},
					{
						Name:        "type",
						Description: "Entrypoint type",
					},
				},
			},
		},
	}
}

func exportedSymbolsCtxBlob() CtxBlob {
	return CtxBlob{
		Name:        "exported-symbols",
		Description: "Exported data (i.e., public functions and variables)",
		Command:     "iEj",
		Schema: []ObjectSchema{
			ObjectSchema{
				Fields: []FieldSchema{
					{
						Name:        "name",
						Description: "The name of the export",
					},
					{
						Name:        "flagname",
						Description: "The name of the export as a rizin flag",
					},
					{
						Name:        "realname",
						Description: "The actual name of the export",
					},
					{
						Name:        "ordinal",
						Description: "The export ordinal",
					},
					{
						Name:        "bind",
						Description: "Scope (i.e., global)",
					},
					{
						Name:        "size",
						Description: "Size of the export",
					},
					{
						Name:        "type",
						Description: "Export type (i.e., function, global variable, or other data)",
					},
					{
						Name:        "vaddr",
						Description: "Virtual address",
					},
					{
						Name:        "paddr",
						Description: "Physical address",
					},
					{
						Name:        "is_imported",
						Description: "Unknown field, ignore",
					},
					{
						Name:        "lib",
						Description: "Unknown field, ignore",
					},
				},
			},
		},
	}
}

func importedSymbolsCtxBlob() CtxBlob {
	return CtxBlob{
		Name:        "imported-symbols",
		Description: "Symbols imported from other libraries by the executable",
		Command:     "iij",
		Schema: []ObjectSchema{
			ObjectSchema{
				Fields: []FieldSchema{
					{
						Name:        "name",
						Description: "The symbol name of the import",
					},
					{
						Name:        "ordinal",
						Description: "The importordinal",
					},
					{
						Name:        "bind",
						Description: "Scope (i.e., global)",
					},
					{
						Name:        "type",
						Description: "Import type (i.e., function, global variable, or other data)",
					},
				},
			},
		},
	}
}

func symbolsCtxBlob() CtxBlob {
	return CtxBlob{
		Name:        "symbols",
		Description: "All symbols references by executable (exports, imports, local functions and code)",
		Command:     "isj",
		Schema: []ObjectSchema{
			ObjectSchema{
				Fields: []FieldSchema{
					{
						Name:        "name",
						Description: "The name of the symbols",
					},
					{
						Name:        "flagname",
						Description: "The name of the symbol as a rizin flag",
					},
					{
						Name:        "realname",
						Description: "The actual name of the symbol",
					},
					{
						Name:        "ordinal",
						Description: "The symbol ordinal",
					},
					{
						Name:        "bind",
						Description: "Scope (i.e., global)",
					},
					{
						Name:        "size",
						Description: "Size of the symbol's data",
					},
					{
						Name:        "type",
						Description: "Symbol type (i.e., function, global variable, or other data)",
					},
					{
						Name:        "vaddr",
						Description: "Virtual address of symbol",
					},
					{
						Name:        "paddr",
						Description: "Physical address of symbol",
					},
					{
						Name:        "is_imported",
						Description: "Set to 'true' if symbol an import",
					},
					{
						Name:        "lib",
						Description: "Source of symbol if imported",
					},
				},
			},
		},
	}
}

func executableSegmentsCtxBlob() CtxBlob {
	return CtxBlob{
		Name:        "executable-segments",
		Description: "All segments in the executable file",
		Command:     "iSSj",
		Schema: []ObjectSchema{
			ObjectSchema{
				Fields: []FieldSchema{
					{
						Name:        "name",
						Description: "The name of the segment",
					},
					{
						Name:        "size",
						Description: "Size of the segment",
					},
					{
						Name:        "vsize",
						Description: "Virtual size of the segment",
					},

					{
						Name:        "perm",
						Description: "The memory permission assigned to the segment in '-rwx' format ('r' = 'read', 'w' = 'writable', 'x' = 'executable')",
					},
					{
						Name:        "align",
						Description: "Segment alignment in bits",
					},
					{
						Name:        "vaddr",
						Description: "Virtual address of segment in base 10 (ignore, currently broken)",
					},
					{
						Name:        "paddr",
						Description: "Physical address of the segment in base 10",
					},
				},
			},
		},
	}
}

func executableSectionsCtxBlob() CtxBlob {
	return CtxBlob{

		Name:        "executable-sections",
		Description: "All sections in the executable file",
		Command:     "iSj",
		Schema: []ObjectSchema{
			ObjectSchema{
				Fields: []FieldSchema{
					{
						Name:        "name",
						Description: "The name of the section",
					},
					{
						Name:        "size",
						Description: "Size of the section",
					},
					{
						Name:        "vsize",
						Description: "Virtual size of the section",
					},
					{
						Name:        "perm",
						Description: "The memory permission assigned to the section in '-rwx' format ('r' = 'read', 'w' = 'writable', 'x' = 'executable')",
					},
					{
						Name:        "type",
						Description: "Section type",
					},
					{
						Name:        "vaddr",
						Description: "Virtual address of section in base 10 (ignore, currently broken)",
					},
					{
						Name:        "paddr",
						Description: "Physical address of the section in base 10",
					},
				},
			},
		},
	}
}

func stringsCtxBlob() CtxBlob {
	return CtxBlob{
		Name:        "executable-strings",
		Description: "All strings in the executable file",
		Command:     "izzj",
		Schema: []ObjectSchema{
			ObjectSchema{
				Fields: []FieldSchema{
					{
						Name:        "section",
						Description: "The name of the section in which the string is found",
					},
					{
						Name:        "size",
						Description: "Size of the string",
					},
					{
						Name:        "length",
						Description: "Length of the string",
					},

					{
						Name:        "vsize",
						Description: "Virtual size of the section",
					},
					{
						Name:        "string",
						Description: "The string's data",
					},
					{
						Name:        "type",
						Description: "String type ('ascii', 'utf8le', 'utf8be', 'utf16le', 'utfbe16')",
					},
					{
						Name:        "vaddr",
						Description: "Virtual address of string in base 10 (ignore, currently broken)",
					},
					{
						Name:        "paddr",
						Description: "Physical address of the string in base 10",
					},
				},
			},
		},
	}
}
