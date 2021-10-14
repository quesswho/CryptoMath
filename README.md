# CryptoMath
A program that implements various hash functions

## Build Windows
1. Download [MYSYS2](https://www.msys2.org/) and follow the instructions, make sure to run 
`pacman -S --needed base-devel mingw-w64-x86_64-toolchain` to install gcc and make
2. Make sure to start MYSYS2 MinGW 64-bit then go to this directory by writing `cd /c/path` where c is the disk C:// and path is the directory. Note that `/` is forward slash.
3. Run `make all`
4. The program can run from the same command line with `make run` or from the executable in the bin folder

## Build Linux
1. Depending on your distro this step might be slightly different. But on Ubuntu you need to run 
```sudo apt update
sudo apt install build-essential```
2. In the terminal run `make all` 