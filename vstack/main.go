package main

import (
	"bufio"
	"errors"
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
	offset    uint64
	stackSize uint64
	stackVars []stackVar
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
	stackInfo, err := afi2StackInfo(bufio.NewScanner(os.Stdin))
	if err != nil {
		return fmt.Errorf("failed to parse afi vars - %w", err)
	}

	err = printStackVars(stackInfo)
	if err != nil {
		return fmt.Errorf("failed to print stack vars - %w", err)
	}

	return nil
}

func afi2StackInfo(scanner *bufio.Scanner) (stackInfo, error) {
	var stack stackInfo

	for scanner.Scan() {
		afiLine := scanner.Text()
		words := strings.Fields(afiLine)

		switch words[0] {
		case "offset:":
			offset, err := strconv.ParseUint(strings.Trim(words[1], "0x"), 16, 64)
			if err != nil {
				return stackInfo{}, fmt.Errorf("failed to parse stackframe - %s", err)
			}

			stack.offset = offset
		case "stackframe:":
			stackSize, err := strconv.ParseUint(words[1], 10, 64)
			if err != nil {
				return stackInfo{}, fmt.Errorf("failed to parse stackframe - %s", err)
			}

			stack.stackSize = stackSize
		case "var":
			sVar, err := parseVarLine(afiLine)
			if err != nil {
				return stackInfo{}, fmt.Errorf("failed to parse var line in afi file - %s", err)
			}

			numStackVars := len(stack.stackVars)
			sVar.addrStart = stack.stackSize - sVar.varOffset
			if numStackVars > 0 {
				lastSVar := &stack.stackVars[numStackVars-1]
				lastSVar.addrEnd = sVar.addrStart - 0x1
				lastSVar.size = lastSVar.addrEnd - lastSVar.addrStart + 0x1

				leftSection := strings.Repeat("-", int(lastSVar.addrStart/0x4))
				midSection := strings.Repeat("x", int(lastSVar.size/0x4))
				sectionSize := int(stack.stackSize / 0x4)
				rightSection := strings.Repeat("-", sectionSize-len(leftSection+midSection))

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
	lastSVar.addrEnd = stack.stackSize - 0x9
	lastSVar.size = lastSVar.addrEnd - lastSVar.addrStart + 0x1

	leftSection := strings.Repeat("-", int(lastSVar.addrStart/0x4))
	midSection := strings.Repeat("x", int(lastSVar.size/0x4))
	sectionSize := int(stack.stackSize / 0x4)
	rightSection := strings.Repeat("-", sectionSize-len(leftSection+midSection))

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
	var hexPad int
	//                      0       1         2        3        4      5       6       7
	tableHeader := []string{"var#", "offset", "start", "range", "end", "size", "type", "name"}
	columnWidth := make([]int, len(tableHeader))
	for i := range columnWidth {
		columnWidth[i] = len(tableHeader[i])
	}

	// change column width based on table data size
	for _, stackVar := range stack.stackVars {
		hexLen := len(fmt.Sprintf("%x", stackVar.varOffset))
		if hexPad < hexLen {
			hexPad = hexLen
		}

		indexLen := utf8.RuneCountInString(strconv.Itoa(len(stack.stackVars)))
		if columnWidth[0] < indexLen {
			columnWidth[0] = indexLen
		}

		offsetLen := len(fmt.Sprintf("rsp-0x%x", stackVar.varOffset))
		if columnWidth[1] < offsetLen {
			columnWidth[1] = offsetLen
		}

		addrStartLen := len(fmt.Sprintf("0x%x", stackVar.addrStart))
		if columnWidth[1] < addrStartLen {
			columnWidth[1] = addrStartLen
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

	hexPadStr := strconv.Itoa(hexPad)

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
			statTable += stackVar.printTopRow(columnWidth, hexPadStr, index, stack.stackSize)
			index++
		}

		if i >= 0 {
			// Add the standard row for the current stack variable
			statTable += stackVar.print(columnWidth, hexPadStr, index)
			index++
		}

		// Add row for saved rbp
		if i == len(stack.stackVars)-1 {
			statTable += stackVar.printBottomRow(columnWidth, hexPadStr, index, stack.stackSize)
		}
	}

	fmt.Println(statTable)

	return nil
}

func (o *stackVar) printTopRow(columnWidth []int, hexPadStr string, index int, stackSize uint64) string {
	return fmt.Sprintf(
		TableFormatString,
		columnWidth[0], index,
		columnWidth[1], fmt.Sprintf("rsp-0x%0"+hexPadStr+"x", stackSize),
		columnWidth[2], fmt.Sprintf("0x%0"+hexPadStr+"x", 0x00),
		columnWidth[3], strings.Repeat("-", int(stackSize/0x4)),
		columnWidth[4], fmt.Sprintf("0x%0"+hexPadStr+"x", o.addrStart-0x1),
		columnWidth[5], "",
		columnWidth[6], "",
		columnWidth[7], "",
	)
}

func (o *stackVar) print(columnWidth []int, hexPadStr string, index int) string {
	return fmt.Sprintf(
		TableFormatString,
		columnWidth[0], index,
		columnWidth[1], fmt.Sprintf("rsp-0x%0"+hexPadStr+"x", o.varOffset),
		columnWidth[2], fmt.Sprintf("0x%0"+hexPadStr+"x", o.addrStart),
		columnWidth[3], o.rangeString,
		columnWidth[4], fmt.Sprintf("0x%0"+hexPadStr+"x", o.addrEnd),
		columnWidth[5], fmt.Sprintf("0x%0"+hexPadStr+"x", o.size),
		columnWidth[6], o.kind,
		columnWidth[7], o.name,
	)
}

func (o *stackVar) printBottomRow(columnWidth []int, hexPadStr string, index int, stackSize uint64) string {
	return fmt.Sprintf(
		TableFormatString,
		columnWidth[0], index,
		columnWidth[1], "rsp-"+fmt.Sprintf("0x%0"+hexPadStr+"x", 0x08),
		columnWidth[2], fmt.Sprintf("0x%0"+hexPadStr+"x", stackSize-0x8),
		columnWidth[3], strings.Repeat("-", int((stackSize-0x8)/0x4))+"xx",
		columnWidth[4], fmt.Sprintf("0x%0"+hexPadStr+"x", stackSize-0x1),
		columnWidth[5], fmt.Sprintf("0x%0"+hexPadStr+"x", 0x08),
		columnWidth[6], "int64_t",
		columnWidth[7], "saved rbp",
	)
}
