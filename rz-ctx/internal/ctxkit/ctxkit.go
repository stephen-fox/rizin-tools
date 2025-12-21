package ctxkit

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/stephen-fox/radareutil"
)

type ParserConfig struct {
	TargetFilePath    string
	OutputDirPath     string
	RizinExePath      string
	AdditionalCliArgs []string
	DebugLogging      *log.Logger
}

func Start(config ParserConfig) (*Parser, error) {
	info, _ := os.Stat(config.OutputDirPath)
	if info != nil {
		if !info.IsDir() {
			return nil, errors.New("output directory already exists as a file")
		}

		entries, _ := os.ReadDir(config.OutputDirPath)
		if len(entries) > 0 {
			return nil, errors.New("a non-empty output directory already exists")
		}
	} else {
		err := os.MkdirAll(config.OutputDirPath, 0o700)
		if err != nil {
			return nil, fmt.Errorf("failed to create output directory: %q - %w",
				config.OutputDirPath, err)
		}
	}

	args := make([]string, len(config.AdditionalCliArgs)+1)

	copy(args, config.AdditionalCliArgs)

	args[len(args)-1] = config.TargetFilePath

	if config.DebugLogging != nil {
		config.DebugLogging.Printf("rizin exe: %q - additonal args: %q",
			config.RizinExePath, args)
	}

	rizinApi, err := radareutil.NewCliApi(&radareutil.Radare2Config{
		AdditionalCliArgs: args,
		ExecutablePath:    config.RizinExePath,
	})
	if err != nil {
		return nil, err
	}

	err = rizinApi.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start rizin - %w", err)
	}

	log.Printf("examining %q...", config.TargetFilePath)

	// TODO: rizin crashes if we try specifying "-q -0" in
	// addition to "-A", so we need to execute the analysis
	// command after startup.
	_, err = rizinApi.Execute("aaa")
	if err != nil {
		return nil, fmt.Errorf("failed to execute analysis commands - %w", err)
	}

	return &Parser{
		rizinApi:      rizinApi,
		outputDirPath: config.OutputDirPath,
	}, nil
}

type Parser struct {
	rizinApi      radareutil.Api
	outputDirPath string
}

func (o *Parser) Close() error {
	o.rizinApi.Kill()

	return nil
}

func (o *Parser) Save(ctx context.Context, blobs []CtxBlob) error {
	for _, blob := range blobs {
		log.Printf("[%s] start", blob.Name)

		err := o.save(ctx, blob)
		if err != nil {
			return fmt.Errorf("failed to save blob: %q - %w",
				blob.Name, err)
		}

		log.Printf("[%s] end", blob.Name)
	}

	return nil
}

func (o *Parser) save(ctx context.Context, blob CtxBlob) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		// Keep going.
	}

	outputDirPath := filepath.Join(o.outputDirPath, blob.Name)

	err := os.MkdirAll(outputDirPath, 0o755)
	if err != nil {
		return fmt.Errorf("failed to create output directory - %w", err)
	}

	humanReadmePath := filepath.Join(outputDirPath, "README.md")

	jsonReadmePath := filepath.Join(outputDirPath, "schema.txt")

	humanReadme, err := os.OpenFile(humanReadmePath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open human readme file - %w", err)
	}
	defer humanReadme.Close()

	jsonReadme, err := os.OpenFile(jsonReadmePath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open json readme file - %w", err)
	}
	defer jsonReadme.Close()

	err = blob.WriteFiles(jsonReadme, humanReadme)
	if err != nil {
		return fmt.Errorf("failed to write readme files - %w", err)
	}

	blobOutputPath := filepath.Join(outputDirPath, blob.Name)
	var optOutput []byte

	switch {
	case blob.RizinFn != nil:
		optOutput, err = blob.RizinFn(RizinFnConfig{
			ParentDir: outputDirPath,
			Api:       o.rizinApi,
		})
		if err != nil {
			return fmt.Errorf("custom rizin function failed - %w", err)
		}

	case blob.Command != "":
		optOutput, err = o.rizinApi.ExecuteToBytes(blob.Command)
		if err != nil {
			return fmt.Errorf("blob rizin command failed - %w", err)
		}
	default:
		return errors.New("both rizin function and command string fields are unset")
	}

	if len(optOutput) > 0 {
		err = os.WriteFile(blobOutputPath, optOutput, 0o644)
		if err != nil {
			return fmt.Errorf("failed to write output from custom rizin command to output file - %w",
				err)
		}
	}

	return nil
}
