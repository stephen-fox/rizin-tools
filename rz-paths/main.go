// rz-paths finds code paths between a child symbol and a parent symbol
// using rizin.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/stephen-fox/radareutil"
)

const (
	appName = "rz-paths"

	usage = appName + `

SYNOPSIS
  ` + appName + ` -` + filePathArg + ` file-path -` + childSymArg + ` child-symbol -` + parentSymArg + ` parent-symbol

DESCRIPTION
  ` + appName + ` finds code paths between a child symbol and a parent symbol
  using rizin.

OPTIONS
`

	rizinExePathArg = "R"
	outputFormatArg = "F"
	helpArg         = "h"
	debugLogArg     = "v"
	filePathArg     = "f"
	archArg         = "a"
	bitsArg         = "b"
	childSymArg     = "c"
	parentSymArg    = "p"
	maxDepthArg     = "d"
	maxRefsArg      = "r"

	prettyFormatName  = "pretty"
	oneLineFormatName = "one-line"
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

	childSym := flag.String(
		childSymArg,
		"",
		"Child `symbol` name")

	parentSym := flag.String(
		parentSymArg,
		"",
		"Parent `symbol` name")

	maxDepth := flag.Uint(
		maxDepthArg,
		0,
		"Only include paths less than n calls deep (0 means no limit)")

	maxRefs := flag.Uint(
		maxRefsArg,
		0,
		"Only parse n refs per node (0 means no limit)")

	outputFormat := flag.String(
		outputFormatArg,
		prettyFormatName,
		"Output `format` ('"+prettyFormatName+"', '"+oneLineFormatName+"')")

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

		if f.Name == archArg || f.Name == bitsArg {
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

	if *arch != "" && *bits == "" {
		return fmt.Errorf("bits argument ('-%s') must be specified when using -%s",
			bitsArg, archArg)
	}

	if *bits != "" && *arch == "" {
		return fmt.Errorf("arch argument ('-%s') must be specified when using -%s",
			archArg, bitsArg)
	}

	rizinApi, err := radareutil.NewCliApi(&radareutil.Radare2Config{
		ExecutablePath: *rizinExePath,
	})
	if err != nil {
		return err
	}

	err = rizinApi.Start()
	if err != nil {
		return err
	}
	defer rizinApi.Kill()

	out, err := rizinApi.Execute("o " + *exePath)
	if err != nil {
		return err
	}

	if out != "" {
		return fmt.Errorf("open failed - %s", out)
	}

	if *arch != "" {
		out, err = rizinApi.Execute("oa " + *arch + " " + *bits)
		if err != nil {
			return err
		}

		if out != "" {
			return fmt.Errorf("set arch and bits failed - %s", out)
		}
	}

	out, err = rizinApi.Execute("aaa")
	if err != nil {
		return err
	}

	var paths []*CodePath

	// TODO: Check that parent ref actually exists via rizin.
	finder := PathFinder{
		Parent:   *parentSym,
		Child:    *childSym,
		MaxDepth: uint(*maxDepth),
		MaxRefs:  uint(*maxRefs),
		Api:      rizinApi,
		OnPathFn: func(p *CodePath) error {
			paths = append(paths, p)
			return nil
		},
	}

	if *debugLog {
		finder.debug = log.New(
			log.Default().Writer(),
			"[debug] ",
			log.Default().Flags()|log.Lmsgprefix)
	}

	err = finder.Lookup()
	if err != nil {
		return err
	}

	for _, p := range paths {
		var callStr string

		switch *outputFormat {
		case prettyFormatName:
			callStr = p.PrettyCallString()
		case oneLineFormatName:
			callStr = p.CallString()
		default:
			return fmt.Errorf("unknown output format: %q", *outputFormat)
		}

		os.Stdout.WriteString(strconv.Itoa(p.Depth) + " " + callStr + "\n")
	}

	return nil
}

type PathFinder struct {
	Parent   string
	Child    string
	MaxDepth uint
	MaxRefs  uint
	OnPathFn func(*CodePath) error
	Api      radareutil.Api
	current  *CodePath
	debug    *log.Logger
}

func (o *PathFinder) removeCurrent() {
	if o.current.Next == nil {
		o.current.Prev = nil

		return
	}

	o.current = o.current.Next
	o.current.Prev = nil
}

func (o *PathFinder) add(pushed *CodePath) {
	if o.current == nil {
		o.current = pushed
		pushed.Depth = 1

		return
	}

	current := o.current

	pushed.Depth = current.Depth + 1
	pushed.Next = current

	current.Prev = pushed

	o.current = pushed
}

func (o *PathFinder) Lookup() error {
	if o.Parent == "" {
		return errors.New("please specify a parent reference")
	}

	if o.Child == "" {
		return errors.New("please specify a child reference")
	}

	if o.OnPathFn == nil {
		return errors.New("please provide a path function")
	}

	out, err := o.Api.Execute("s " + o.Child)
	if err != nil {
		return err
	}

	if out != "" {
		return fmt.Errorf("failed to seek to %q - %s", o.Child, out)
	}

	out, err = o.Api.Execute("s")
	if err != nil {
		return err
	}

	if out == "" {
		return fmt.Errorf("failed to get address of %q - %s", o.Child, out)
	}

	addr, err := parseHexAddr(out)
	if err != nil {
		return fmt.Errorf("failed to get end func's address - %w", err)
	}

	return o.lookupRecurse(o.Child, addr)
}

func (o *PathFinder) lookupRecurse(id string, addr uintptr) error {
	if o.debug != nil {
		o.debug.Printf("lookup %q (current: %q)",
			id, o.current.Sym)
	}

	if o.current != nil {
		if o.MaxDepth > 0 && o.current.Depth > int(o.MaxDepth) {
			return nil
		}

		if o.current.nextContains(id) {
			if o.debug != nil {
				o.debug.Printf("skip %q because it already exists", id)
			}

			return nil
		}
	}

	o.add(&CodePath{
		Sym:  id,
		Addr: addr,
	})
	defer o.removeCurrent()

	if id == o.Parent {
		if o.debug != nil {
			o.debug.Printf("found path: on %q | depth: %d",
				o.current.Sym, o.current.Depth)
		}

		current := o.current.clone()
		current.setIndex(0)

		if o.debug != nil {
			o.debug.Printf("end clone")
		}

		err := o.OnPathFn(current)
		if err != nil {
			return fmt.Errorf("on path func failed - %w", err)
		}

		return nil
	}

	out, err := o.Api.Execute("s " + id)
	if err != nil {
		return err
	}

	if out != "" {
		return fmt.Errorf("failed to seek to %q - %s", id, out)
	}

	out, err = o.Api.Execute("axt")
	if err != nil {
		return err
	}

	if out == "" {
		return nil
	}

	refs, err := parseAxtRefs(out)
	if err != nil {
		return fmt.Errorf("failed to parse axt refs to %q - %w",
			id, err)
	}

	if o.MaxRefs > 0 && len(refs) > int(o.MaxRefs) {
		refs = refs[0:o.MaxRefs]
	}

	for _, r := range refs {
		err = o.lookupRecurse(r.symbol, r.addr)
		if err != nil {
			return fmt.Errorf("failed to lookup ref %s (0x%x) -> %s (0x%x) - %w",
				r.symbol, r.addr, id, addr, err)
		}
	}

	return nil
}

type CodePath struct {
	Sym   string
	Addr  uintptr
	Prev  *CodePath
	Next  *CodePath
	Depth int
	Index int
}

func (o *CodePath) CallString() string {
	current := o.String()

	if o.Next == nil {
		return current
	}

	return current + " -> " + o.Next.CallString()
}

func (o *CodePath) PrettyCallString() string {
	current := strings.Repeat("  ", o.Index)

	if o.Prev != nil {
		current += "+ "
	}

	current += o.String()

	if o.Next == nil {
		return current
	}

	current += "\n"
	current += o.Next.PrettyCallString()

	return current
}

func (o *CodePath) String() string {
	return fmt.Sprintf("%s (0x%x)", o.Sym, o.Addr)
}

func (o *CodePath) setIndex(i int) {
	o.Index = i

	if o.Next != nil {
		o.Next.setIndex(i + 1)
	}
}

func (o *CodePath) clone() *CodePath {
	pathCopy := o.cloneNoRecurse()

	if o.Next != nil {
		pathCopy.Next = o.Next.clone()
	}

	return pathCopy
}

func (o *CodePath) cloneNoRecurse() *CodePath {
	pathCopy := &CodePath{
		Sym:   o.Sym,
		Addr:  o.Addr,
		Depth: o.Depth,
		Index: o.Index,
		Next:  o.Next,
		Prev:  o.Prev,
	}

	return pathCopy
}

func (o *CodePath) nextContains(sym string) bool {
	if o.Next == nil {
		return false
	}

	//if o.Next.Sym+strconv.FormatUint(uint64(o.Addr), 10) == sym+strconv.FormatUint(uint64(o.Addr), 10) {
	if o.Next.Sym == sym {
		return true
	}

	return o.Next.nextContains(sym)
}

func (o *CodePath) resetTo(other *CodePath) {
	o.Sym = other.Sym
	o.Addr = other.Addr
	o.Depth = other.Depth
	o.Index = other.Index
	o.Next = other.Next
	o.Prev = other.Prev
}

func parseAxtRefs(out string) ([]ref, error) {
	var refs []ref
	visited := make(map[string]struct{})

	scanner := bufio.NewScanner(strings.NewReader(out))

	for scanner.Scan() {
		line := scanner.Text()

		r, isValid, err := parseAxtLine(line)
		if err != nil {
			return nil, fmt.Errorf("failed to parse axt line: %q - %w",
				line, err)
		}

		if !isValid {
			continue
		}

		_, alreadyVisited := visited[r.symbol]
		if !alreadyVisited {
			refs = append(refs, r)
		}
	}

	if scanner.Err() != nil {
		return nil, scanner.Err()
	}

	return refs, nil
}

func parseAxtLine(line string) (ref, bool, error) {
	if line == "" || strings.HasPrefix(line, "(nofunc)") || strings.Contains(line, " invalid") {
		return ref{}, false, nil
	}

	fields := strings.Fields(line)

	addrStr := fields[1]

	addr, err := parseHexAddr(addrStr)
	if err != nil {
		return ref{}, false, fmt.Errorf("failed to parse address %q - %w",
			addrStr, err)
	}

	return ref{
		symbol: fields[0],
		addr:   uintptr(addr),
	}, true, nil
}

type ref struct {
	symbol string
	addr   uintptr
}

func parseHexAddr(addrStr string) (uintptr, error) {
	noPrefix := strings.TrimPrefix(addrStr, "0x")
	need := 16 - len(noPrefix)
	if need > 0 {
		noPrefix = strings.Repeat("0", need) + noPrefix
	}

	addrBytes, err := hex.DecodeString(noPrefix)
	if err != nil {
		return 0, fmt.Errorf("failed to hex decode %q - %w",
			noPrefix, err)
	}

	return uintptr(binary.BigEndian.Uint64(addrBytes)), nil
}
