# rz-paths

rz-paths finds code paths between a child symbold and parent symbol
using rizin.

## Usage

```sh
rz-paths -f file-path -c child-symbol -p parent-symbol
```

## Example

```console
$ rz-paths -f ./libsystem_asl.dylib -c sym.imp.malloc -p sym._syslog
4 sym._syslog (0x185bcefe8)
  + sym.__vsyslog (0x185bdd97c)
    + sym.__asl_lib_vlog (0x185bcbf14)
      + sym.imp.malloc (0x185bde520)
7 sym._syslog (0x185bcefe8)
  + sym.__vsyslog (0x185bdd97c)
    + sym.__asl_lib_vlog (0x185bcbff8)
      + sym.__asl_send_message (0x185bcc624)
        + sym.__asl_send_message_text (0x185bd17c8)
          + sym._asl_format_message (0x185bcf924)
            + sym.imp.malloc (0x185bde520)
6 sym._syslog (0x185bcefe8)
  + sym.__vsyslog (0x185bdd940)
    + sym.__asl_lib_vlog_text (0x185bd15c8)
      + sym.__asl_send_message_text (0x185bd17c8)
        + sym._asl_format_message (0x185bcf924)
          + sym.imp.malloc (0x185bde520)
(...)
$ # Filter to a maximum call depth:
$ rz-paths -f ./libsystem_asl.dylib -c sym.imp.malloc -p sym._syslog -d 4
4 sym._syslog (0x185bcefe8)
  + sym.__vsyslog (0x185bdd97c)
    + sym.__asl_lib_vlog (0x185bcbf14)
      + sym.imp.malloc (0x185bde520)
```

## Installation

```sh
go install gitlab.com/stephen-fox/rizin-tools/rz-paths@latest
```
