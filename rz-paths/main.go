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
	onlyNPathsArg   = "N"
	uniquePathsArg  = "U"
	helpArg         = "h"
	debugLogArg     = "v"
	filePathArg     = "f"
	archArg         = "a"
	bitsArg         = "b"
	childSymArg     = "c"
	parentSymArg    = "p"
	interSymArg     = "i"
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

	onlyNPaths := flag.Uint(
		onlyNPathsArg,
		0,
		"Stop after finding n paths (0 means no limit)")

	onlyUniquePaths := flag.Bool(
		uniquePathsArg,
		false,
		"Only include paths with unique symbols")

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

	var intermediateSymbols stringMapArg
	flag.Var(
		&intermediateSymbols,
		interSymArg,
		"Optionally require the presence of a `symbol` between parent and child\n"+
			"(may be specified more than once)")

	maxDepth := flag.Uint(
		maxDepthArg,
		0,
		"Only include paths less than n calls deep (0 means no limit)")

	maxRefs := flag.Uint(
		maxRefsArg,
		0,
		"Skip node if it has more than n refs (0 means no limit)")

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

		switch f.Name {
		case archArg, bitsArg, interSymArg:
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

	extraRizinArgs = append(extraRizinArgs, *exePath)

	rizinApi, err := radareutil.NewCliApi(&radareutil.Radare2Config{
		AdditionalCliArgs: extraRizinArgs,
		ExecutablePath:    *rizinExePath,
	})
	if err != nil {
		return err
	}

	err = rizinApi.Start()
	if err != nil {
		return err
	}
	defer rizinApi.Kill()

	// TODO: rizin crashes if we try specifying "-q -0" in
	// addition to "-A", so we need to execute the analysis
	// command after startup.
	_, err = rizinApi.Execute("aaa")
	if err != nil {
		return fmt.Errorf("failed to execute analysis commands - %w", err)
	}

	var paths []*CodePath

	// TODO: Check that parent ref actually exists via rizin.
	finder := PathFinder{
		Parent:   *parentSym,
		Child:    *childSym,
		Inters:   intermediateSymbols.values,
		MaxDepth: uint(*maxDepth),
		MaxRefs:  uint(*maxRefs),
		Unique:   *onlyUniquePaths,
		Api:      rizinApi,
		OnPathFn: func(p *CodePath) error {
			paths = append(paths, p)

			if *onlyNPaths > 0 && len(paths) == int(*onlyNPaths) {
				return stopLookingErr
			}

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
	if err != nil && !errors.Is(err, stopLookingErr) {
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

var stopLookingErr = errors.New("stop looking")

type PathFinder struct {
	Parent   string
	Child    string
	Inters   map[string]struct{}
	MaxDepth uint
	MaxRefs  uint
	Unique   bool
	OnPathFn func(*CodePath) error
	Api      radareutil.Api
	visited  map[string]struct{}
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

	if o.Unique {
		o.visited = make(map[string]struct{})
	}

	out, err := o.Api.Execute("s " + o.Child)
	if err != nil {
		return fmt.Errorf("failed to seek to %q - %w",
			o.Child, err)
	}

	if out != "" {
		return fmt.Errorf("failed to seek to %q - rizin error: %s",
			o.Child, out)
	}

	out, err = o.Api.Execute("s")
	if err != nil {
		return fmt.Errorf("failed to get address of %q - %w",
			o.Child, err)
	}

	if out == "" {
		return fmt.Errorf("failed to get address of %q - rizin error: %s",
			o.Child, out)
	}

	addr, err := parseHexAddr(out)
	if err != nil {
		return fmt.Errorf("failed to get end func's address - %w", err)
	}

	return o.lookupRecurse(o.Child, addr)
}

func (o *PathFinder) lookupRecurse(id string, addr uintptr) error {
	if o.debug != nil {
		if o.current == nil {
			o.debug.Printf("lookup %q (iniital lookup)",
				id)
		} else {
			o.debug.Printf("lookup %q (current: %q)",
				id, o.current.Sym)
		}
	}

	if o.current != nil {
		if o.MaxDepth > 0 && o.current.Depth+1 > int(o.MaxDepth) {
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

		if o.visited != nil {
			str := o.current.uniqueSymCallString()

			_, alreadySeen := o.visited[str]
			if alreadySeen {
				return nil
			}

			o.visited[str] = struct{}{}
		}

		if len(o.Inters) > 0 {
			for intermediateSym := range o.Inters {
				if !o.current.nextContains(intermediateSym) {
					return nil
				}
			}
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
		return fmt.Errorf("failed to seek to %q - %w", id, err)
	}

	if out != "" {
		return fmt.Errorf("failed to seek to %q - rizin error: %s",
			id, out)
	}

	out, err = o.Api.Execute("axt")
	if err != nil {
		return fmt.Errorf("failed to get references to %q - %w",
			id, err)
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
		log.Printf("[warn] skipping %q (0x%x) because it has %d references which exceeds the configured maximum of %d",
			id, addr, len(refs), o.MaxRefs)

		return nil
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

func (o *CodePath) uniqueSymCallString() string {
	current := o.Sym + "\x00"

	if o.Next == nil {
		return current
	}

	return current + o.Next.uniqueSymCallString()
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
	// We are not using the JSON output because rizin currently
	// does not include the symbol name :(

	if line == "" || strings.HasPrefix(line, "(nofunc)") || strings.Contains(line, " invalid") {
		return ref{}, false, nil
	}

	// Examples:
	// sym._syslog_DARWIN_EXTSN 0x185bcea9c [CALL] bl sym.__vsyslog
	// sym.func.100007408; switch table (4 cases) at 0x1000077b8 0x1000075c0 [CODE] br x16
	fields := strings.Fields(line)

	addrStr := fields[1]

	addr, err := parseHexAddr(addrStr)
	if err != nil {
		// TODO: Some axt references are not truly
		// space-delimited. For now, just forgo
		// including the address if we cannot parse
		// the string.
		//
		//return ref{}, false, fmt.Errorf("failed to parse address %q - %w",
		//	addrStr, err)
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
