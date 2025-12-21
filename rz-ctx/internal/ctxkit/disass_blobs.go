package ctxkit

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
)

func textSectionDisassCtxBlob() CtxBlob {
	return CtxBlob{
		Name:        "text-section-disassembly",
		Description: "Full disassembly of the .text (code) section delimited by newlines",
		RizinFn:     textSectionDisass,
		Schema: TextSchema{
			Description: "Each line of text contains one of two possible objects. Both objects contain two fields separated by one or more space characters. Each object starts with a base 16 offset in the executable, followed by either the symbol name (e.g., function name) or the CPU instruction found at that offset",
			Separator:   "newline",
			Objects: []ObjectSchema{
				{
					Fields: []FieldSchema{
						{
							Name:        "current symbol name",
							Description: "Offset followed by three spaces and then the current symbol name",
						},
						{
							Name:        "current CPU instruction assembly",
							Description: "Offset followed by single space and then the CPU instruction's assembly",
						},
					},
				},
			},
		},
	}
}

func textSectionDisass(config RizinFnConfig) ([]byte, error) {
	currentSeek, err := config.Api.Execute("s")
	if err != nil {
		return nil, fmt.Errorf("failed to get current seek address - %w",
			err)
	}

	sectionsJson, err := config.Api.ExecuteToBytes("iSj")
	if err != nil {
		return nil, fmt.Errorf("failed to get sections json - %w",
			err)
	}

	type section struct {
		Name  string `json:"name"`
		Vsize uint64 `json:"vsize"`
		Vaddr uint64 `json:"vaddr"`
	}

	var sections []section

	err = json.Unmarshal(sectionsJson, &sections)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sections json ('%s') - %w",
			sectionsJson, err)
	}

	var text *section
	var visitied []string

	for _, section := range sections {
		if section.Name == ".text" {
			text = &section
			break
		}

		visitied = append(visitied, section.Name)
	}

	if text == nil {
		return nil, fmt.Errorf("failed to find text section in sections (visited: %q)",
			visitied)
	}

	_, err = config.Api.Execute("s " + strconv.FormatUint(text.Vaddr, 16))
	if err != nil {
		return nil, fmt.Errorf("failed to seek to start of text section at %#x - %w",
			text.Vaddr, err)
	}
	defer func() {
		_, _ = config.Api.Execute("s " + currentSeek)
	}()

	disass, err := config.Api.ExecuteToBytes("pDq " + strconv.FormatUint(text.Vsize, 10))
	if err != nil {
		return nil, fmt.Errorf("failed to print text section disassembly - %w", err)
	}

	return disass, nil
}

func functionsDisassCtxBlob() CtxBlob {
	return CtxBlob{
		Name:        "all-functions-disassembly",
		Description: "Disassembly of all functions in the executable",
		RizinFn:     disassAllFunctions,
		Schema: ObjectSchema{
			Fields: []FieldSchema{
				{
					Name:        "name",
					Description: "Function name",
				},
				{
					Name:        "size",
					Description: "Size of the function",
				},
				{
					Name:        "addr",
					Description: "Offset of function in base 10",
				},
				{
					Name:        "ops",
					Description: "Array of objects describing each CPU instruction in the function",
					ChildObjects: []ObjectSchema{
						{
							Fields: []FieldSchema{
								{
									Name:        "offset",
									Description: "The offset of the CPU instruction within the executable in base 10",
								},
								{
									Name:        "esil",
									Description: "The CPU instruction in ESIL (Evaluable Strings Intermediate Languag) format",
								},
								{
									Name:        "refptr",
									Description: "Set to true if the CPU instruction references data using a pointer",
								},
								{
									Name:        "fcn_addr",
									Description: "Address of CPU instruction's function",
								},
								{
									Name:        "fcn_last",
									Description: "",
								},
								{
									Name:        "size",
									Description: "The size of the CPU instruction in bytes",
								},
								{
									Name:        "opcode",
									Description: "CPU instruction as assembly without rizin annotations or flags",
								},
								{
									Name:        "disasm",
									Description: "CPU instruction sassembly with rizin annotations and flags included",
								},
								{
									Name:        "bytes",
									Description: "CPU instruction binary data as a hex-encoded string",
								},
								{
									Name:        "family",
									Description: "",
								},
								{
									Name:        "type",
									Description: "CPU instruction type",
								},
								{
									Name:        "reloc",
									Description: "true if the CPU instruction references a relocation, false if not",
								},
								{
									Name:        "type_num",
									Description: "",
								},
								{
									Name:        "type2_num",
									Description: "",
								},
								{
									Name:        "flags",
									Description: "An array containing the rizin flags associated with the CPU instruction",
								},
								{
									Name:        "comment",
									Description: "Comment at a base64-encoded string",
								},
							},
						},
					},
				},
			},
		},
	}
}

func disassAllFunctions(config RizinFnConfig) ([]byte, error) {
	currentSeek, err := config.Api.Execute("s")
	if err != nil {
		return nil, fmt.Errorf("failed to get current seek address - %w",
			err)
	}
	defer func() {
		_, _ = config.Api.Execute("s " + currentSeek)
	}()

	_, err = config.Api.Execute("fs functions")
	if err != nil {
		return nil, fmt.Errorf("failed to set current flagspace to functions - %w",
			err)
	}

	functionFlagsJson, err := config.Api.ExecuteToBytes("flj")
	if err != nil {
		return nil, fmt.Errorf("failed to get function flags json - %w")
	}

	type flag struct {
		Name string `json:"name"`
	}

	var flags []flag

	err = json.Unmarshal(functionFlagsJson, &flags)
	if err != nil {
		return nil, fmt.Errorf("failed to parse function flags json - %w", err)
	}

	for _, fn := range flags {
		err := checkStringForFsUse(fn.Name)
		if err != nil {
			return nil, fmt.Errorf("function name is unsafe for filesystem use: %q - %w",
				fn.Name, err)
		}

		_, err = config.Api.Execute("s " + fn.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to seek to function: %q - %w",
				fn.Name, err)
		}

		disass, err := config.Api.ExecuteToBytes("pdfj")
		if err != nil {
			return nil, fmt.Errorf("failed to print function disassembly for %q - %w",
				fn.Name, err)
		}

		outputDir := filepath.Join(config.ParentDir, fn.Name)

		err = os.MkdirAll(outputDir, 0o755)
		if err != nil {
			return nil, fmt.Errorf("failed to create output directory for function %q - %w",
				fn.Name, err)
		}

		outputFilePath := filepath.Join(outputDir, fn.Name+".txt")

		err = os.WriteFile(outputFilePath, disass, 0o644)
		if err != nil {
			return nil, fmt.Errorf("failed to write function disassembly file to %q - %w",
				outputFilePath, err)
		}
	}

	return nil, nil
}

func checkStringForFsUse(str string) error {
	cleaned := path.Clean(str)
	if cleaned != str {
		return fmt.Errorf("string is different after path.Clean - became: %q", cleaned)
	}

	cleaned = filepath.Clean(str)
	if cleaned != str {
		return fmt.Errorf("string is different after filepath.Clean - became: %q", cleaned)
	}

	return nil
}
