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
	kind        string
	name        string
	offset      uint64
	addrStart   uint64
	rangeString string
	addrEnd     uint64
	size        uint64
}

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

func mainWithError() error {
	stackVars, stackSize, err := afi2StackVars(bufio.NewScanner(os.Stdin))
	if err != nil {
		return fmt.Errorf("failed to parse afi vars - %w", err)
	}

	//for i, _ := range stackVars {
	//	println(i, "/", stackVars[i].kind, "/", stackVars[i].name, "/", stackVars[i].offset)
	//}

	stackVars, err = getVarRanges(stackVars, stackSize)
	if err != nil {
		return fmt.Errorf("failed to get var ranges - %w", err)
	}

	err = printStackVars(stackVars, stackSize)
	if err != nil {
		return fmt.Errorf("failed to print stack vars - %w", err)
	}

	return nil
}

// function that can parse one line of text from afi output
func afi2StackVars(scanner *bufio.Scanner) ([]stackVar, uint64, error) {
	var varSlice []stackVar
	var stackSize uint64

	for scanner.Scan() {
		line := scanner.Text()
		words := strings.Fields(line)

		switch words[0] {
		case "stackframe:":
			value, err := strconv.ParseUint(words[1], 10, 64)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to parse stackframe - %s", err)
			}

			stackSize = value
		case "var":
			stackVar, err := parseVarLine(line)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to parse var line - %s", err)
			}
			varSlice = append(varSlice, stackVar)
		default:
			//continue
		}
	}

	return varSlice, stackSize, nil
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
		kind:   strings.Join(typeNameSection[1:len(typeNameSection)-1], " "),
		name:   typeNameSection[len(typeNameSection)-1],
		offset: offset,
	}

	return newStackVar, nil
}

func getVarRanges(stackVars []stackVar, stackSize uint64) ([]stackVar, error) {
	// Calculate rangeSize in terms of 4-byte chunks
	rangeSize := int(stackSize / 0x4)

	for i := range stackVars {
		// Calculate addrStart
		stackVars[i].addrStart = stackSize - stackVars[i].offset

		// Calculate addrEnd
		if i < len(stackVars)-1 {
			stackVars[i].addrEnd = stackSize - stackVars[i+1].offset - 0x1
		} else {
			stackVars[i].addrEnd = stackSize - 0x8 - 0x1
		}

		// Calculate size
		stackVars[i].size = stackVars[i].addrEnd - stackVars[i].addrStart + 0x1

		// Build rangeString
		startBlocks := int(stackVars[i].addrStart / 0x4)
		sizeBlocks := int(stackVars[i].size / 0x4)
		if startBlocks+sizeBlocks > rangeSize {
			return nil, fmt.Errorf("rangeString exceeds rangeSize for variable at index %d", i)
		}

		stackVars[i].rangeString = strings.Repeat("-", startBlocks) +
			strings.Repeat("x", sizeBlocks)

		// Pad remaining range
		padding := rangeSize - len(stackVars[i].rangeString)
		if padding > 0 {
			stackVars[i].rangeString += strings.Repeat("-", padding)
		}
	}

	return stackVars, nil
}

func printStackVars(stackVars []stackVar, stackSize uint64) error {
	//                      0       1         2        3        4      5       6       7
	tableHeader := []string{"var#", "offset", "start", "range", "end", "size", "type", "name"}
	columnWidth := make([]int, len(tableHeader))
	for i := range columnWidth {
		columnWidth[i] = len(tableHeader[i])
	}

	// Change column width based on table data size
	for _, stackVar := range stackVars {
		indexLen := utf8.RuneCountInString(strconv.Itoa(len(stackVars)))
		if columnWidth[0] < indexLen {
			columnWidth[0] = indexLen
		}

		offsetLen := len(fmt.Sprintf("rsp-0x%x", stackVar.offset))
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

	var statTable string
	columnPadding := 2
	// Add column padding and table header
	for i := range columnWidth {
		columnWidth[i] += columnPadding
		statTable += fmt.Sprintf("%-*s", columnWidth[i], tableHeader[i])
	}

	// Add new line after table header
	statTable += "\n"

	for i, stackVar := range stackVars {
		index := i

		// Handle the special case where the first stack variable does not start at 0x0
		if i == 0 && stackVar.addrStart != 0x0 {
			statTable += fmt.Sprintf(
				"%-*d%-*s%-*s%-*s%-*s%-*s%-*s%-*s\n",
				columnWidth[0], index,
				columnWidth[1], fmt.Sprintf("rsp-0x%x", stackSize),
				columnWidth[2], "0x00",
				columnWidth[3], strings.Repeat("-", int(stackSize/0x4)),
				columnWidth[4], fmt.Sprintf("0x%x", stackVars[0].addrStart-0x1),
				columnWidth[5], "",
				columnWidth[6], "",
				columnWidth[7], "",
			)
			index++
		}

		// Add the standard row for the current stack variable
		statTable += fmt.Sprintf(
			"%-*d%-*s%-*s%-*s%-*s%-*s%-*s%-*s\n",
			columnWidth[0], index,
			columnWidth[1], fmt.Sprintf("rsp-0x%x", stackVar.offset),
			columnWidth[2], fmt.Sprintf("0x%x", stackVar.addrStart),
			columnWidth[3], stackVar.rangeString,
			columnWidth[4], fmt.Sprintf("0x%x", stackVar.addrEnd),
			columnWidth[5], fmt.Sprintf("0x%x", stackVar.size),
			columnWidth[6], stackVar.kind,
			columnWidth[7], stackVar.name,
		)

		// Add row for saved rbp
		if i == len(stackVars)-1 {
			statTable += fmt.Sprintf(
				"%-*d%-*s%-*s%-*s%-*s%-*s%-*s%-*s\n",
				columnWidth[0], index,
				columnWidth[1], "rsp-0x08",
				columnWidth[2], fmt.Sprintf("0x%x", stackSize-0x8),
				columnWidth[3], strings.Repeat("-", int((stackSize-0x8)/0x4))+"xx",
				columnWidth[4], fmt.Sprintf("0x%x", stackSize-0x1),
				columnWidth[5], "0x8",
				columnWidth[6], "int64_t",
				columnWidth[7], "saved rbp",
			)
		}
	}

	fmt.Println(statTable)

	return nil
}
