# vstack

vstack visualizes the stack variables of a function based on rizin's afi output,
supporting only 64-bit programs.

## Usage

To use vstack, pipe the output from rizin afi into the program:

```sh
$ vstack -rsp rsp-address < afi-output.txt
```

## Example Output

```txt
$ vstack -rsp 0xebd8 < afi-output.txt
var#  offset    start   range                   end     size  type        name
0     rsp-0x58  0xeb80  ----------------------  0xeb83
1     rsp-0x54  0xeb84  -x--------------------  0xeb87  0x4   uint64_t    dbg_copy_M
2     rsp-0x50  0xeb88  --xx------------------  0xeb8f  0x8   const char  *input_copy_M
3     rsp-0x48  0xeb90  ----xx----------------  0xeb97  0x8   int64_t     var_48h
4     rsp-0x40  0xeb98  ------xx--------------  0xeb9f  0x8   char        *s
5     rsp-0x38  0xeba0  --------xxxxxx--------  0xebb7  0x18  const char  *format
6     rsp-0x20  0xebb8  --------------xxxx----  0xebc7  0x10  int64_t     function_to_call
7     rsp-0x10  0xebc8  ------------------xx--  0xebcf  0x8   int64_t     canary
8     rsp-0x8   0xebd0  --------------------xx  0xebd7  0x8   int64_t     saved rbp
```
