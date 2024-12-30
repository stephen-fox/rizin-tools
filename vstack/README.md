# vstack

vstack visualizes the stack variables of a function based on rizin's afi output,
supporting only 64-bit programs.

## Usage

To use vstack, pipe the output from rizin afi into the program:

```sh
$ cat afi.txt | ./vstack
```

## Example Output

```txt
var#  offset    start  range                   end   size  type        name
0     rsp-0x58  0x00   ----------------------  0x3
1     rsp-0x54  0x4    -x--------------------  0x7   0x4   uint64_t    dbg_copy_M
2     rsp-0x50  0x8    --xx------------------  0xf   0x8   const char  *input_copy_M
3     rsp-0x48  0x10   ----xx----------------  0x17  0x8   int64_t     var_48h
4     rsp-0x40  0x18   ------xx--------------  0x1f  0x8   char        *s
5     rsp-0x38  0x20   --------xxxxxx--------  0x37  0x18  const char  *format
6     rsp-0x20  0x38   --------------xxxx----  0x47  0x10  int64_t     function_to_call
7     rsp-0x10  0x48   ------------------xx--  0x4f  0x8   int64_t     canary
8     rsp-0x08  0x50   --------------------xx  0x57  8     int64_t     saved rbp
```
