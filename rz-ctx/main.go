// rz-ctx
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"gitlab.com/stephen-fox/rizin-tools/rz-ctx/internal/ctxkit"
)

const (
	appName = "rz-paths"

	usage = appName + `

SYNOPSIS
  ` + appName + ` -` + filePathArg + ` file-path -` + outputDirPathArg + ` output-dir

DESCRIPTION
  ` + appName + ` extracts context from rizin into a directory.

OPTIONS
`

	rizinExePathArg  = "R"
	helpArg          = "h"
	debugLogArg      = "v"
	filePathArg      = "f"
	archArg          = "a"
	bitsArg          = "b"
	outputDirPathArg = "o"
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

func mainWithError() error {
	rizinExePath := flag.String(
		rizinExePathArg,
		"rizin",
		"The rizin executable `path` to use")

	help := flag.Bool(
		helpArg,
		false,
		"Display this information")

	debugLog := flag.Bool(
		debugLogArg,
		false,
		"Enable debug logging")

	exePath := flag.String(
		filePathArg,
		"",
		"File `path` to examine")

	arch := flag.String(
		archArg,
		"",
		"Target platform `architecture`")

	bits := flag.String(
		bitsArg,
		"",
		"Target platform `bits`")

	outputDirPath := flag.String(
		outputDirPathArg,
		"",
		"The directory to save files to")

	flag.Parse()

	if *help {
		os.Stderr.WriteString(usage)
		flag.PrintDefaults()

		os.Exit(1)
	}

	var err error
	flag.VisitAll(func(f *flag.Flag) {
		if err != nil {
			return
		}

		switch f.Name {
		case archArg, bitsArg:
			return
		}

		if f.Value.String() == "" {
			err = fmt.Errorf("please specify '-%s' - %s",
				f.Name, f.Usage)
		}
	})
	if err != nil {
		return err
	}

	var extraRizinArgs []string

	if *arch != "" {
		extraRizinArgs = append(extraRizinArgs, "-a", *arch)
	}

	if *bits != "" {
		extraRizinArgs = append(extraRizinArgs, "-b", *bits)
	}

	if flag.NArg() > 0 {
		extraRizinArgs = append(extraRizinArgs, flag.Args()...)
	}

	ctx, cancelFn := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer cancelFn()

	var debug *log.Logger
	if *debugLog {
		debug = log.Default()
	}

	parser, err := ctxkit.Start(ctxkit.ParserConfig{
		TargetFilePath:    *exePath,
		OutputDirPath:     *outputDirPath,
		RizinExePath:      *rizinExePath,
		AdditionalCliArgs: extraRizinArgs,
		DebugLogging:      debug,
	})
	if err != nil {
		return fmt.Errorf("failed to start rizin ctx parser - %w", err)
	}
	defer parser.Close()

	err = parser.Save(ctx, ctxkit.DefaultCtxBlobs())
	if err != nil {
		return fmt.Errorf("failed to save rizin context blobs - %w", err)
	}

	return nil
}

type stringMapArg struct {
	values map[string]struct{}
}

func (o *stringMapArg) String() string {
	if len(o.values) == 0 {
		return ""
	}

	strs := make([]string, len(o.values))

	i := 0
	for s := range o.values {
		strs[i] = s
		i++
	}

	return strings.Join(strs, ", ")
}

func (o *stringMapArg) Set(s string) error {
	if o.values == nil {
		o.values = make(map[string]struct{})
	}

	o.values[s] = struct{}{}

	return nil
}
