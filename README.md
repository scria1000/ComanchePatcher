# ComanchePatcher

## Description
This command line tool patches the executable of the 1998 game Comanche Gold to allow it to run without requiring the CD

## Overview
![image](https://github.com/scria1000/ComanchePatcher/assets/91804886/3815ddb5-672a-4acd-9ea2-188a25f5928b)

## Usage
```
Usage: patcher [command] [arguments]

Commands:

  patch <target>               Patch Comanche Gold exe
  copy <source> <destination>  Copy KDV.PFF from Comanche Gold CD directory

Options:

  -?, -h, --help               Print usage text.

Examples:

  patcher patch
  patcher patch Wc3.exe
  patcher patch "C:\Comanche Gold\Wc3.exe"

  patcher copy E:\ .
  patcher copy E:\ KDV.PFF
  patcher copy E:\C3G\KDV.PFF "C:\Games\Comanche Gold\KDV.PFF"
```

## Building from Source
Tested with [Zig](https://ziglang.org/) `0.11.0` and `0.12.0-dev.2835+256c5934b`.
```
zig build
```
