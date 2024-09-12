# library-exports

library-exports.sh creates a list of function signatures for a library's
exported symbols using rizin. The script's output can be used to stub out
a proxy library.

## Usage

```
library-exports.sh /path/to/library
```

## Example

```console
$ library-exports.sh foo.dll                   
void Example1(int32_t arg_4h, int32_t arg_10h, int32_t arg_ch, int32_t arg_8h);
void Example2(int32_t arg_4h, int32_t arg_814h);
void Example3(int32_t arg_4h);
```
