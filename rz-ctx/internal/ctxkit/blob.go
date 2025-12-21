package ctxkit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/stephen-fox/radareutil"
)

type CtxBlob struct {
	Name        string
	Description string
	ParentDir   string
	Command     string
	RizinFn     func(RizinFnConfig) ([]byte, error) `json:"-"`
	Schema      BlobSchema
}

func (o CtxBlob) WriteFiles(jsonReadme io.Writer, humanReadme io.Writer) error {
	err := json.NewEncoder(jsonReadme).Encode(o)
	if err != nil {
		return fmt.Errorf("failed to encode and write json readme - %w", err)
	}

	buf := bytes.NewBuffer([]byte(fmt.Sprintf("# %s\n\n%s\n",
		o.Name, o.Description)))

	if o.Command != "" {
		buf.WriteString("\n# rizin command\n\n```sh\n" + o.Command + "\n```\n")
	}

	_, err = humanReadme.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to write human readme - %w", err)
	}

	return nil
}

type RizinFnConfig struct {
	ParentDir string
	Api       radareutil.Api
}

type BlobSchema interface{}

type ObjectSchema struct {
	Fields []FieldSchema
}

type FieldSchema struct {
	Name         string
	Description  string
	ChildObjects []ObjectSchema
}

type TextSchema struct {
	Description string
	Separator   string
	Objects     []ObjectSchema
}

func DefaultCtxBlobs() []CtxBlob {
	return []CtxBlob{
		executableInfoCtxBlob(),
		executableEntrypointsCtxBlob(),
		exportedSymbolsCtxBlob(),
		importedSymbolsCtxBlob(),
		symbolsCtxBlob(),
		executableSegmentsCtxBlob(),
		executableSectionsCtxBlob(),
		stringsCtxBlob(),
		textSectionDisassCtxBlob(),
		functionsDisassCtxBlob(),
	}
}
