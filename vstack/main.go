package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

type stackVar struct {
	varOffset   uint64
	addrStart   uint64
	rangeString string
	addrEnd     uint64
	size        uint64
	kind        string
	name        string
}

type stackInfo struct {
	size      uint64
	stackVars []stackVar
	rsp       uint64
}

var (
	TableFormatString = "%-*d%-*s%-*s%-*s%-*s%-*s%-*s%-*s\n"
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

func mainWithError() error {
	rspStr := flag.String(
		"rsp",
		"0x00",
		"Address of rsp register at the start of the function.")

	flag.Parse()

	rsp, err := strconv.ParseUint(strings.TrimPrefix(*rspStr, "0x"), 16, 64)
	if err != nil {
		return fmt.Errorf("failed to parse rsp to uint - %s", err)
	}

	stackInfo, err := afi2StackInfo(bufio.NewScanner(os.Stdin), rsp)
	if err != nil {
		return fmt.Errorf("failed to parse afi vars - %w", err)
	}

	err = printStackVars(stackInfo)
	if err != nil {
		return fmt.Errorf("failed to print stack vars - %w", err)
	}

	return nil
}

func afi2StackInfo(scanner *bufio.Scanner, rsp uint64) (stackInfo, error) {
	var stack stackInfo

	for scanner.Scan() {
		afiLine := scanner.Text()
		words := strings.Fields(afiLine)

		switch words[0] {
		case "stackframe:":
			stackSize, err := strconv.ParseUint(words[1], 10, 64)
			if err != nil {
				return stackInfo{}, fmt.Errorf("failed to parse stackframe to uint - %s", err)
			}

			stack.size = stackSize

			if rsp == 0 {
				stack.rsp = stackSize
			} else {
				stack.rsp = rsp
			}
		case "var":
			sVar, err := parseVarLine(afiLine)
			if err != nil {
				return stackInfo{}, fmt.Errorf("failed to parse var line in afi file - %s", err)
			}

			numStackVars := len(stack.stackVars)
			sVar.addrStart = stack.rsp - sVar.varOffset
			if numStackVars > 0 {
				lastSVar := &stack.stackVars[numStackVars-1]
				lastSVar.addrEnd = sVar.addrStart - 0x1
				lastSVar.size = lastSVar.addrEnd - lastSVar.addrStart + 0x1

				leftSection := strings.Repeat("-", int((stack.size-(stack.rsp-lastSVar.addrStart))/0x4))
				midSection := strings.Repeat("x", int(lastSVar.size/0x4))
				rightSection := strings.Repeat("-", int(stack.size/0x4)-len(leftSection+midSection)+2)
				lastSVar.rangeString = leftSection + midSection + rightSection
			}

			stack.stackVars = append(stack.stackVars, sVar)
		default:
			//continue
		}
	}

	if scanner.Err() != nil {
		return stackInfo{}, fmt.Errorf("failed to read from input - %w", scanner.Err())
	}

	// for the last stack var
	lastSVar := &stack.stackVars[len(stack.stackVars)-1]
	lastSVar.addrEnd = stack.rsp - 0x9
	lastSVar.size = lastSVar.addrEnd - lastSVar.addrStart + 0x1

	leftSection := strings.Repeat("-", int((stack.size-(stack.rsp-lastSVar.addrStart))/0x4))
	midSection := strings.Repeat("x", int(lastSVar.size/0x4))
	sectionSize := int(stack.size / 0x4)
	rightSection := strings.Repeat("-", sectionSize-len(leftSection+midSection)+2)

	lastSVar.rangeString = leftSection + midSection + rightSection

	return stack, nil
}

func parseVarLine(line string) (stackVar, error) {
	line = strings.Replace(line, "  { }", "", 1)
	typeNameSectionStr, offsetSectionStr, found := strings.Cut(line, "@")
	if !found {
		return stackVar{}, errors.New("failed to find '@' in var line")
	}

	typeNameSection := strings.Fields(typeNameSectionStr)
	offsetSection := strings.Fields(offsetSectionStr)
	offset, err := strconv.ParseUint(strings.TrimPrefix(offsetSection[2], "0x"), 16, 64)
	if err != nil {
		return stackVar{}, fmt.Errorf("failed to parse var offset - %w", err)
	}

	newStackVar := stackVar{
		kind:      strings.Join(typeNameSection[1:len(typeNameSection)-1], " "),
		name:      typeNameSection[len(typeNameSection)-1],
		varOffset: offset,
	}

	return newStackVar, nil
}

func printStackVars(stack stackInfo) error {
	//                      0       1         2        3        4      5       6       7
	tableHeader := []string{"var#", "offset", "start", "range", "end", "size", "type", "name"}
	columnWidth := make([]int, len(tableHeader))
	for i := range columnWidth {
		columnWidth[i] = len(tableHeader[i])
	}

	hexPadStr := strconv.Itoa(len(fmt.Sprintf("%x", stack.stackVars[0].addrStart)))

	// change column width based on table data size
	for _, stackVar := range stack.stackVars {

		indexLen := utf8.RuneCountInString(strconv.Itoa(len(stack.stackVars)))
		if columnWidth[0] < indexLen {
			columnWidth[0] = indexLen
		}

		offsetLen := len(fmt.Sprintf("rsp-0x%x", stackVar.varOffset))
		if columnWidth[1] < offsetLen {
			columnWidth[1] = offsetLen
		}

		addrStartLen := len(fmt.Sprintf("0x%0"+hexPadStr+"x", stackVar.addrStart))
		if columnWidth[2] < addrStartLen {
			columnWidth[2] = addrStartLen
		}

		rangeStringLen := len(stackVar.rangeString)
		if columnWidth[3] < rangeStringLen {
			columnWidth[3] = rangeStringLen
		}

		addrEndLen := len(fmt.Sprintf("0x%x", stackVar.addrEnd))
		if columnWidth[4] < addrEndLen {
			columnWidth[4] = addrEndLen
		}

		sizeLen := len(fmt.Sprintf("0x%x", stackVar.size))
		if columnWidth[4] < sizeLen {
			columnWidth[4] = sizeLen
		}

		kindLen := len(stackVar.kind)
		if columnWidth[6] < kindLen {
			columnWidth[6] = kindLen
		}

		nameLen := len(stackVar.name)
		if columnWidth[7] < nameLen {
			columnWidth[7] = nameLen
		}
	}

	var statTable string
	columnPadding := 2
	// Add column padding and table header
	for i := range columnWidth {
		columnWidth[i] += columnPadding
		statTable += fmt.Sprintf("%-*s", columnWidth[i], tableHeader[i])
	}

	// Add new line after table header
	statTable += "\n"

	index := 0
	for i, stackVar := range stack.stackVars {
		// Handle the special case where the first stack variable does not start at 0x0
		if i == 0 && stackVar.addrStart != 0x0 {
			statTable += stackVar.printTopRow(columnWidth, hexPadStr, index, stack)
			index++
		}

		if i >= 0 {
			// Add the standard row for the current stack variable
			statTable += stackVar.print(columnWidth, hexPadStr, index)
			index++
		}

		// Add row for saved rbp
		if i == len(stack.stackVars)-1 {
			// to show the location of rbp considering stack alignment
			if (stack.rsp-0x8)%0x8 != 0 {
				statTable += stackVar.printBottomRow(columnWidth, hexPadStr, index, stack)
			} else {
				statTable += stackVar.printBottomEmptyRow(true, columnWidth, hexPadStr, index, stack)
				statTable += stackVar.printBottomEmptyRow(false, columnWidth, hexPadStr, index, stack)
			}
		}
	}

	fmt.Println(statTable)

	return nil
}

func (o *stackVar) printTopRow(columnWidth []int, hexPadStr string, index int, stack stackInfo) string {
	return fmt.Sprintf(
		TableFormatString,
		columnWidth[0], index,
		columnWidth[1], fmt.Sprintf("rsp-0x%0x", stack.size),
		columnWidth[2], fmt.Sprintf("0x%0"+hexPadStr+"x", stack.rsp-stack.size),
		columnWidth[3], strings.Repeat("-", int(stack.size/0x4)+2),
		columnWidth[4], fmt.Sprintf("0x%0x", o.addrStart-0x1),
		columnWidth[5], "",
		columnWidth[6], "",
		columnWidth[7], "",
	)
}

func (o *stackVar) print(columnWidth []int, hexPadStr string, index int) string {
	return fmt.Sprintf(
		TableFormatString,
		columnWidth[0], index,
		columnWidth[1], fmt.Sprintf("rsp-0x%0x", o.varOffset),
		columnWidth[2], fmt.Sprintf("0x%0"+hexPadStr+"x", o.addrStart),
		columnWidth[3], o.rangeString,
		columnWidth[4], fmt.Sprintf("0x%0"+hexPadStr+"x", o.addrEnd),
		columnWidth[5], fmt.Sprintf("0x%0x", o.size),
		columnWidth[6], o.kind,
		columnWidth[7], o.name,
	)
}

// for alignment spacing before the rbp on the stack
func (o *stackVar) printBottomEmptyRow(isPadding bool, columnWidth []int, hexPadStr string, index int, stack stackInfo) string {
	var printString string

	if isPadding {
		printString = fmt.Sprintf(
			TableFormatString,
			columnWidth[0], index,
			columnWidth[1], "rsp-"+fmt.Sprintf("0x%0x", 0x08),
			columnWidth[2], fmt.Sprintf("0x%0"+hexPadStr+"x", stack.rsp-0x8),
			columnWidth[3], strings.Repeat("-", int((stack.size-0x8)/0x4))+"xx--",
			columnWidth[4], fmt.Sprintf("0x%0"+hexPadStr+"x", stack.rsp-0x1),
			columnWidth[5], fmt.Sprintf("0x%0x", 0x08),
			columnWidth[6], "int64_t",
			columnWidth[7], "padding",
		)
	} else {
		printString = fmt.Sprintf(
			TableFormatString,
			columnWidth[0], index,
			columnWidth[1], "rsp",
			columnWidth[2], fmt.Sprintf("0x%0"+hexPadStr+"x", stack.rsp),
			columnWidth[3], strings.Repeat("-", int((stack.size)/0x4))+"xx",
			columnWidth[4], fmt.Sprintf("0x%0"+hexPadStr+"x", stack.rsp+0x7),
			columnWidth[5], fmt.Sprintf("0x%0x", 0x08),
			columnWidth[6], "int64_t",
			columnWidth[7], "saved rbp",
		)
	}

	return printString
}

func (o *stackVar) printBottomRow(columnWidth []int, hexPadStr string, index int, stack stackInfo) string {
	return fmt.Sprintf(
		TableFormatString,
		columnWidth[0], index,
		columnWidth[1], "rsp-"+fmt.Sprintf("0x%0x", 0x08),
		columnWidth[2], fmt.Sprintf("0x%0"+hexPadStr+"x", stack.rsp-0x8),
		columnWidth[3], strings.Repeat("-", int((stack.size-0x8)/0x4))+"xx",
		columnWidth[4], fmt.Sprintf("0x%0"+hexPadStr+"x", stack.rsp-0x1),
		columnWidth[5], fmt.Sprintf("0x%0x", 0x08),
		columnWidth[6], "int64_t",
		columnWidth[7], "saved rbp",
	)
}
