# MsgDmpDecoder

[![Latest Release](https://img.shields.io/github/v/release/basondole/MsgDmpDecoder?display_name=tag&sort=semver)](https://github.com/basondole/MsgDmpDecoder/releases)
[![Build Status](https://github.com/basondole/MsgDmpDecoder/actions/workflows/rust-release.yml/badge.svg)](https://github.com/basondole/MsgDmpDecoder/actions/workflows/rust-release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/basondole/MsgDmpDecoder)](https://goreportcard.com/report/github.com/basondole/MsgDmpDecoder)
[![Issues](https://img.shields.io/github/issues/basondole/MsgDmpDecoder)](https://github.com/basondole/MsgDmpDecoder/issues)
[![License](https://img.shields.io/github/license/basondole/MsgDmpDecoder)](https://github.com/basondole/MsgDmpDecoder)


# Background

Recently I was experimenting with BGP. Because I was doing unconventional
things, the Cisco device I was using rightfully kept complaining and dumping
BGP messages on the logs.

It is kinda hard to make out what the BGP hex means with the naked eye past the
first 19 bytes. For the uninitiated; the first 16 bytes are markers, 17th and
18th are length and 19th is the message type (*look at packet captures for long
enough and you can read these with naked eye*). Cisco does not have a public
web endpoint to decipher the message dumps (if they have I couldnt find it), so
I made my own. A script to dicepher those `MSGDUMP` logs.

In my experimenting... I ended up with multiple scripts in different languages
(*because why not learn a new language while breaking BGP?*). Nevertheless, I
made sure to use the same design pattern in all of them. So, except for
language specific quirks the scripts are very identical.


# Example Logs

Some examples of BGP messages dump in logs.

```
%BGP-4-MSGDUMP: unsupported or mal-formatted message received from 10.3.3.3: 
FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0041 0104 5BA0 00B4 0303 0303 2402 0601 
0400 0100 8002 0601 0400 0100 0102 0280 0002 0202 0002 0246 0002 0641 0400 068D 
B8
```

```
%BGP-6-MSGDUMP_LIMIT: unsupported or mal-formatted message received from 10.14.41.1: 
FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 003F 0200 0000 2740 0101 0040 0212 0204 
0000 07D0 0000 07D0 0000 07D0 0000 07D0 4003 049B 103D 0680 0404 0000 07D0 00
*Sep 16 20:10:37.231: %BGP-6-MALFORMEDATTR: Malformed attribute in (BGP(0) Prefixes: 0.0.0.0/0 ) received from 10.14.41.1
```

```
%BGP-3-NOTIFICATION: sent to neighbor 10.10.10.10 3/1 (update malformed) 188  bytes F0630BB8 00000000 00000000 00000000 00
BGP: 10.10.10.10 Bad attributes FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0118
0200 0000 FD40 0101 0040 0206 0202 0D1C 316E 4003 04C3 10A1 6180 0404 0000 0000 4005 0400 0000 3CC0 081C 0D1C 0002 0D1C 0016 0D1C 0056 0D1C
01F7 0D1C 029A 0D1C 0813 FDE8 FDDE F063 0BB8 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 185D AF90
```

```
%BGP-6-ASPATH: Long AS path 2828 6762 262589 262589 262589 262589 28146 28146 28146 28146 263862 263862 263862 263862 263862 263862 263862 263862 received from 209.119.92.241: BGP(0) Prefixes: 138.186.118.0/24
Jun  9 09:09:44: %BGP-6-MSGDUMP_LIMIT: unsupported or mal-formatted message received from 209.119.92.241:
FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 007A 0200 0000 5F40 0101 0040 024A 0212
0000 0B0C 0000 0DA3 0004 01BD 0004 01BD 0000 6E42 0000 6E42 0000 6E42 0004 05B8
0004 05B8 0004 05B8 0004 05B8 0004 05B8 0004 05B8 0004 05B8 0004 05B8 0004 05B8
0004 05B8 0004 05B8 4003 04D1 765C F180 0404 0000 0003 18B1 8867
```

```
%BGP-4-MSGDUMP: unsupported or mal-formatted message received from 10.44.17.15: 
FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF0055 0104 3DBA 00B4 0A2C 110F 3802 06010400 0100 0102 0280 0002 0202 0002 06410400 003D BA02 0840 0600 7800 0101 00021405 1200 0100 0100 0200 0100 0200 02000100 8000 02
```

# Usage Examples

Note: The script only generates a `.pcap` file in your home directory. You'd
still need a compatible program to open the file e.g.,
[Wireshark](https://www.wireshark.org/).

## Python

```shell
via 🐍 v3.14.3
❯ python -V
Python 3.14.3

via 🐍 v3.14.3
❯ python msgdmp-to-pcap.py "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0041 0104 5BA0 00B4 0303 0303 2402 0601
 0400 0100 8002 0601 0400 0100 0102 0280 0002 0202 0002 0246 0002 0641 0400 068D
 B8"

============================================================
PCAP CREATED SUCCESSFULLY
============================================================
Full path       : /Users/basondole/bgp_dump.pcap
File size       : 159 bytes
Ethernet frame  : 119 bytes
BGP payload     : 65 bytes
BGP message     : OPEN (type 1)
BGP length      : 65 bytes
============================================================
```

## Typescript

Using Bun runtime.

```shell
via   
❯ bun -v
1.3.14

via   
❯ bun run msgdmp-to-pcap.ts "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0118
0200 0000 FD40 0101 0040 0206 0202 0D1C 316E 4003 04C3 10A1 6180 0404 0000 0000 4005 0400 0000 3CC0 081C 0D1C 0002 0D1C 0016 0D1C 0056 0D1C
01F7 0D1C 029A 0D1C 0813 FDE8 FDDE F063 0BB8 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 185D AF90"

============================================================
PCAP CREATED SUCCESSFULLY
============================================================
Full path       : /Users/basondole/bgp_dump.pcap
File size       : 374 bytes
Ethernet frame  : 334 bytes
BGP payload     : 280 bytes
BGP message     : UPDATE (type 2)
BGP length      : 280 bytes
============================================================
```




## Go


```shell
via  v1.27.1
❯ go version
go version go1.27.1 darwin/amd64

via  v1.27.1
❯ go run msgdmp-to-pcap.go "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 003F 0200 0000 2740 0101 0040 0212 0204  
0000 07D0 0000 07D0 0000 07D0 0000 07D0 4003 049B 103D 0680 0404 0000 07D0 00"

============================================================
PCAP CREATED SUCCESSFULLY
============================================================
Full path       : /Users/basondole/bgp_dump.pcap
File size       : 157 bytes
Ethernet frame  : 117 bytes
BGP payload     : 63 bytes
BGP message     : UPDATE (type 2)
BGP length      : 63 bytes
============================================================
```


## Rust

To run a standalone file as a script in Rust we need the feature prototyped
under the experimental `-Zscript` flag in nightly versions of rust.

```shell
via 🦀 v1.98.1 
❯ rustc --version
rustc 1.98.1 (48a229cea 2026-09-01)

via 🦀 v1.98.1 
❯ cargo +nightly run -Zscript --manifest-path msgdmp-to-pcap.rs "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0041 0104 5BA0 00B4 0303 0303 2402 0601
 0400 0100 8002 0601 0400 0100 0102 0280 0002 0202 0002 0246 0002 0641 0400 068D
 B8"
...

============================================================
PCAP CREATED SUCCESSFULLY
============================================================
Full path       : /Users/basondole/bgp_dump.pcap
File size       : 159 bytes
Ethernet frame  : 119 bytes
BGP payload     : 65 bytes
BGP message     : OPEN (type 1)
BGP length      : 65 bytes
============================================================

```

Alternatively using a tool `rust-script`

```shell
via 🦀 v1.98.1 
❯ cargo install rust-script
...
via 🦀 v1.98.1 took 50s 
❯ rust-script msgdmp-to-pcap.rs "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0041 0104 5BA0 00B4 0303 0303 2402 0601
 0400 0100 8002 0601 0400 0100 0102 0280 0002 0202 0002 0246 0002 0641 0400 068D
 B8"

============================================================
PCAP CREATED SUCCESSFULLY
============================================================
Full path       : /Users/basondole/bgp_dump.pcap
File size       : 159 bytes
Ethernet frame  : 119 bytes
BGP payload     : 65 bytes
BGP message     : OPEN (type 1)
BGP length      : 65 bytes
============================================================

```


## Java

```shell
via ☕ v26.0.2
❯ java --version
openjdk 26.0.2.1 2026-08-18
OpenJDK Runtime Environment Temurin-26.0.2.1+1 (build 26.0.2.1+1)
OpenJDK 64-Bit Server VM Temurin-26.0.2.1+1 (build 26.0.2.1+1, mixed mode)

via ☕ v26.0.2
❯ java msgdmp-to-pcap.java "FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0118
0200 0000 FD40 0101 0040 0206 0202 0D1C 316E 4003 04C3 10A1 6180 0404 0000 0000 4005 0400 0000 3CC0 081C 0D1C 0002 0D1C 0016 0D1C 0056 0D1C
01F7 0D1C 029A 0D1C 0813 FDE8 FDDE F063 0BB8 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
0000 0000 0000 0000
0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 185D AF90"

============================================================
PCAP CREATED SUCCESSFULLY
============================================================
Full path       : /Users/basondole/bgp_dump.pcap
File size       : 374 bytes
Ethernet frame  : 334 bytes
BGP payload     : 280 bytes
BGP message     : UPDATE (type 2)
BGP length      : 280 bytes
============================================================
```


# Building a binary

You can build an executable binary and add it to your environment PATH so that
it is accessble globally in your system.

## Bun

Binaries created by Bun will be a relatively larger file as it includes the Bun
JavaScript runtime in the executable.

**MacOS**

```shell
via   
❯ bun build msgdmp-to-pcap.ts --compile --target=bun-darwin-x64 --minify --outfile ~/bin/msgdmp-to-pcap
  [19ms]  minify  -18.71 KB (estimate)
  [11ms]  bundle  1 modules
[12.412s] compile  /Users/basondole/bin/msgdmp-to-pcap

via   
❯ ll ~/bin
.rwx------ foo foo 66 MB Fri Sep 18 17:27:01 2026  msgdmp-to-pcap
```

**Windows**

```shell
via   
❯ bun build msgdmp-to-pcap.ts --compile --target=bun-windows-x64 --outfile ~/bin/msgdmp-to-pcap.exe
   [7ms]  bundle  1 modules
 [426ms] compile  /Users/basondole/bin/msgdmp-to-pcap.exe

via   
❯ which msgdmp-to-pcap
/Users/basondole/bin/msgdmp-to-pcap

via   
❯ ll ~/bin
.a--- ? ? 94 MB Fri Sep 18 19:37:30 2026  /Users/basondole/bin/msgdmp-to-pcap.exe
```



## Go

Go binaries are relatively larger in size compared to Rust and C since they
include things like the go runtime, garbage collector etc in order to produce
self-contained executables without relying very much on OS libraries.


```shell
via  v1.27.1
❯  go build -o ~/bin/msgdmp-to-pcap.exe msgdmp-to-pcap.go

via  v1.27.1
❯  which msgdmp-to-pcap
/Users/basondole/bin/msgdmp-to-pcap

via  v1.27.1
❯  ll ~/bin
.a--- ? ? 2.7 MB Fri Sep 18 20:03:50 2026  /Users/basondole/bin/msgdmp-to-pcap.exe

```


## Rust

```shell
via 🦀 v1.98.1 
❯ rustc --version
rustc 1.98.1 (48a229cea 2026-09-01)

via 🦀 v1.98.1 
❯ rustc msgdmp-to-pcap.rs -o ~/bin/msgdmp-to-pcap

via 🦀 v1.98.1 
❯ ll ~/bin
.rwxr-xr-x foo foo 562 KB Fri Sep 18 23:53:58 2026  msgdmp-to-pcap

via 🦀 v1.98.1 
❯ file ~/bin/msgdmp-to-pcap
/Users/basondole/bin/msgdmp-to-pcap: Mach-O 64-bit executable x86_64
```

## C

C binary has the smallest size as it benefits from OS libraries so it doesn't
need to bundle a bunch of extra things in its binary.

```shell
via C v16.0.0-clang
❯ cc -std=c11 -Wall -Wextra -O2 msgdmp-to-pcap.c -o ~/bin/msgdmp-to-pcap

via C v16.0.0-clang
❯ ll ~/bin/msgdmp*
.rwxr-xr-x foo staff  13 KB Sun Sep 20 14:45:51 2026  /Users/basondole/bin/msgdmp-to-pcap

via C v16.0.0-clang
❯ which msgdmp-to-pcap
/Users/basondole/bin/msgdmp-to-pcap

via C v16.0.0-clang
❯ file ~/bin/msgdmp-to-pcap
/Users/basondole/bin/msgdmp-to-pcap: Mach-O 64-bit executable x86_64
```

## Benchmarking For Nerds

If you are going to write something in multiple languages, the least you can do
is throw in some benchmarking.

Things to note:
- Not testing pre compiled binaries since some of the languages are interpreted.
- First run for rust when using `rust-script` includes compile time. It is
  cached thereafter.
- Go is slower due to compilation overhead. Because `go run` compiles every
  time.


```shell
❯ export BGP_HEX="FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF 0118
 0200 0000 FD40 0101 0040 0206 0202 0D1C 316E 4003 04C3 10A1 6180 0404 0000 0000 4005 0400 0000 3CC0 081C 0D1C 0002 0D1C 0016 0D1C 0056 0D1C
 01F7 0D1C 029A 0D1C 0813 FDE8 FDDE F063 0BB8 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000
 0000 0000 0000 0000
 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 185D AF90"
```

### Test 1

10 runs ignoring the first run this gives rust and edge since the first run of
`rust-script` will include compile time. Subsequent runs of `rust-script` use
cached binary so will be much faster.

```shell
via C v16.0.0-clang via  v1.27.1 via ☕ v26.0.2 via  via 🐍 v3.13.14 via 🦀 v1.98.1 
❯ hyperfine --runs 10 --warmup 1 \
  'go run msgdmp-to-pcap.go $BGP_HEX' \
  'python msgdmp-to-pcap.py $BGP_HEX' \
  'bun run msgdmp-to-pcap.ts $BGP_HEX' \
  'rust-script msgdmp-to-pcap.rs $BGP_HEX' \
  'java msgdmp-to-pcap.java $BGP_HEX'
Benchmark 1: go run msgdmp-to-pcap.go $BGP_HEX
  Time (mean ± σ):     147.9 ms ±  31.6 ms    [User: 69.8 ms, System: 100.0 ms]
  Range (min … max):   125.9 ms … 232.6 ms    10 runs
 
Benchmark 2: python msgdmp-to-pcap.py $BGP_HEX
  Time (mean ± σ):     131.0 ms ±  19.4 ms    [User: 48.7 ms, System: 19.8 ms]
  Range (min … max):   105.8 ms … 170.9 ms    10 runs
 
Benchmark 3: bun run msgdmp-to-pcap.ts $BGP_HEX
  Time (mean ± σ):      31.2 ms ±   1.8 ms    [User: 7.6 ms, System: 10.0 ms]
  Range (min … max):    28.2 ms …  34.0 ms    10 runs
 
Benchmark 4: rust-script msgdmp-to-pcap.rs $BGP_HEX
  Time (mean ± σ):      11.9 ms ±   1.6 ms    [User: 3.3 ms, System: 3.3 ms]
  Range (min … max):     9.4 ms …  14.2 ms    10 runs
 
Benchmark 5: java msgdmp-to-pcap.java $BGP_HEX
  Time (mean ± σ):     906.7 ms ±  58.2 ms    [User: 1403.3 ms, System: 143.7 ms]
  Range (min … max):   836.9 ms … 1003.2 ms    10 runs
 
Summary
  rust-script msgdmp-to-pcap.rs $BGP_HEX ran
    2.62 ± 0.39 times faster than bun run msgdmp-to-pcap.ts $BGP_HEX
   11.00 ± 2.21 times faster than python msgdmp-to-pcap.py $BGP_HEX
   12.42 ± 3.14 times faster than go run msgdmp-to-pcap.go $BGP_HEX
   76.14 ± 11.44 times faster than java msgdmp-to-pcap.java $BGP_HEX
```

### Test 2

20 runs including first run.

> Not sure if we can say Bun wins or Rust wins since Bun is written in rust
under the hood. You'll be the judge :)

```shell
via C v16.0.0-clang via  v1.27.1 via ☕ v26.0.2 via  via 🐍 v3.13.14 via 🦀 v1.98.1
❯ hyperfine --runs 20 \
  'go run msgdmp-to-pcap.go $BGP_HEX' \
  'python msgdmp-to-pcap.py $BGP_HEX' \
  'bun run msgdmp-to-pcap.ts $BGP_HEX' \
  'rust-script msgdmp-to-pcap.rs $BGP_HEX' \
  'java msgdmp-to-pcap.java $BGP_HEX'
Benchmark 1: go run msgdmp-to-pcap.go $BGP_HEX
  Time (mean ± σ):     179.3 ms ±  24.8 ms    [User: 69.0 ms, System: 97.4 ms]
  Range (min … max):   139.4 ms … 236.8 ms    20 runs
 
Benchmark 2: python msgdmp-to-pcap.py $BGP_HEX
  Time (mean ± σ):     111.2 ms ±  18.9 ms    [User: 45.7 ms, System: 19.5 ms]
  Range (min … max):   100.8 ms … 178.9 ms    20 runs
 
Benchmark 3: bun run msgdmp-to-pcap.ts $BGP_HEX
  Time (mean ± σ):      31.5 ms ±   2.2 ms    [User: 7.4 ms, System: 10.0 ms]
  Range (min … max):    28.4 ms …  36.2 ms    20 runs
 
Benchmark 4: rust-script msgdmp-to-pcap.rs $BGP_HEX
  Time (mean ± σ):      61.4 ms ± 219.1 ms    [User: 3.4 ms, System: 3.6 ms]
  Range (min … max):    10.4 ms … 992.1 ms    20 runs
 
Benchmark 5: java msgdmp-to-pcap.java $BGP_HEX
  Time (mean ± σ):     907.8 ms ±  51.6 ms    [User: 1393.5 ms, System: 145.5 ms]
  Range (min … max):   835.2 ms … 1021.3 ms    20 runs
 
Summary
  bun run msgdmp-to-pcap.ts $BGP_HEX ran
    1.95 ± 6.95 times faster than rust-script msgdmp-to-pcap.rs $BGP_HEX
    3.53 ± 0.65 times faster than python msgdmp-to-pcap.py $BGP_HEX
    5.69 ± 0.88 times faster than go run msgdmp-to-pcap.go $BGP_HEX
   28.79 ± 2.58 times faster than java msgdmp-to-pcap.java $BGP_HEX
```


## Errors Presentation

This below is a bad message dump. I mean it is not really a BGP message I just
put some hex together to make it look like one.

```shell
MsgDmpDecoder🔒 
❯ export BAD_HEX="FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFF  FFFF FFFF FFFF FFFF  0013 0400" 
```

**Java**

```
MsgDmpDecoder🔒 on  master [!?] via ☕ v26.0.2
❯ java src/msgdmp-to-pcap.java $BAD_HEX
Exception in thread "main" java.lang.IllegalArgumentException: Unexpected BGP payload length: 36 (BGP header declares 65535)
        at MsgdmpToPcap.bgpMessage(msgdmp-to-pcap.java:240)
        at MsgdmpToPcap.generatePcap(msgdmp-to-pcap.java:554)
        at MsgdmpToPcap.main(msgdmp-to-pcap.java:673)
```


**Python**

```shell
MsgDmpDecoder🔒 on  master [!?] via 🐍 v3.13.14
❯ python src/msgdmp-to-pcap.py $BAD_HEX
Traceback (most recent call last):
  File "/Volumes/Shared/dev/MsgDmpDecoder/src/msgdmp-to-pcap.py", line 666, in <module>
    sys.exit(main(sys.argv))
             ~~~~^^^^^^^^^^
  File "/Volumes/Shared/dev/MsgDmpDecoder/src/msgdmp-to-pcap.py", line 655, in main
    return generate_pcap(
        "".join(args[1:]),
    ...<4 lines>...
        ),
    )
  File "/Volumes/Shared/dev/MsgDmpDecoder/src/msgdmp-to-pcap.py", line 565, in generate_pcap
    (message := bgp_message(bgp_hex)), options
                ~~~~~~~~~~~^^^^^^^^^
  File "/Volumes/Shared/dev/MsgDmpDecoder/src/msgdmp-to-pcap.py", line 240, in bgp_message
    assert len(message) == length, (
           ^^^^^^^^^^^^^^^^^^^^^^
AssertionError: Unexpected BGP payload length: 36 (BGP header declares 65535)
```

Yes! You are right. The traceback is kind of overwhelming and scary for the
point it makes.

**Rust**

```shell
MsgDmpDecoder🔒 on  master [!?] via 🦀 v1.98.1 
❯ rust-script src/msgdmp-to-pcap.rs $BAD_HEX

thread 'main' (158630) panicked at /Volumes/Shared/dev/MsgDmpDecoder/src/msgdmp-to-pcap.rs:201:5:
assertion `left == right` failed: Unexpected BGP payload length: 36 (BGP header declares 65535)
  left: 36
 right: 65535
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```


**TypeScript**

```shell
MsgDmpDecoder🔒 on  master [!?] via 
❯ bun run src/msgdmp-to-pcap.ts $BAD_HEX
151 |     }
152 |     // The 16th and 17th bytes are the 2 bytes for the Length field.
153 |     // BGP length is big-endian.
154 |     const length = message.readUInt16BE(16);
155 |     if (message.length !== length) {
156 |         throw new Error(
                        ^
error: Unexpected BGP payload length: 36 (BGP header declares 65535)
      at bgpMessage (/Volumes/Shared/dev/MsgDmpDecoder/src/msgdmp-to-pcap.ts:156:19)
      at run (/Volumes/Shared/dev/MsgDmpDecoder/src/msgdmp-to-pcap.ts:712:21)
      at /Volumes/Shared/dev/MsgDmpDecoder/src/msgdmp-to-pcap.ts:750:7

Bun v1.4.2 (macOS x64)
```

**Go**

```shell
MsgDmpDecoder🔒 on  master [!?] via  v1.27.1
❯ go run src/msgdmp-to-pcap.go $BAD_HEX
error: unexpected BGP payload length: 36 bytes (BGP header declares 65535)
exit status 1
```

**C**

```shell
MsgDmpDecoder🔒 on  master [!?] via C v16.0.0-clang
❯ msgdmp-to-pcap $BAD_HEX
Error: Unexpected BGP payload length: 36 (BGP header declares 65535)
```

