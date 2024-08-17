# library-exports

Generates a list of a library's exported symbols. This is potentially useful
for generating a proxy library.

## Usage

```
library-exports.sh /path/to/library
```

## Example

```console
$ library-exports.sh foo.dll                   
void sym.foo.dll_Example1(int32_t arg_4h, int32_t arg_10h, int32_t arg_ch, int32_t arg_8h);
void sym.foo.dll_Example2(int32_t arg_4h, int32_t arg_814h);
void sym.foo.dll_Example3(int32_t arg_4h);
```
