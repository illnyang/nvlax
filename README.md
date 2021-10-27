<p align="center">
    <img src="https://img.shields.io/badge/target%20os-linux-cornflowerblue.svg" alt="target os: linux"/></a>
    <a href="https://opensource.org/licenses/GPL-3.0"><img src="https://img.shields.io/badge/license-GPL%20v3-darkred.svg" alt="license: GPL v3"/></a>
    <a href="https://cmake.org/"><img src="https://img.shields.io/badge/powered%20by-CMake-darkgreen.svg" alt="powered by: CMake" /></a>
    <a href="https://github.com/cpm-cmake/CPM.cmake"><img src="https://img.shields.io/badge/powered%20by-CPM-blue.svg" alt="powered by: CPM" /></a>
    <a href="https://github.com/zyantific/zydis"><img src="https://img.shields.io/badge/powered%20by-Zydis-lightblue.svg" alt="powered by: Zydis" /></a>
    <a href="https://github.com/lief-project/LIEF"><img src="https://img.shields.io/badge/powered%20by-LIEF-mediumblue.svg" alt="powered by: LIEF" /></a>
</p>

<h1 align="center">nvlax</h1>
<p align="center">Future-proof NvENC & NvFBC patcher</p>

# Requirements
- Working internet connection during configuration (i.e cloning does NOT include dependencies)
- CMake
- C++ compiler

# Building

```bash
git clone 'https://github.com/illnyang/nvlax.git'
cd nvlax
mkdir build && cd build
cmake ..
make
```

# Example of usage

## Patch NvENC in-place:

```bash
# nvlax_encode -i /usr/lib/libnvidia-encode.so.495.44 -o /usr/lib/libnvidia-encode.so.495.44
```
## Patch NvFBC in-place:

```bash
# nvlax_fbc -i /usr/lib/libnvidia-fbc.so.495.44 -o /usr/lib/libnvidia-fbc.so.495.44
```

# FAQ

#### How is this more future-proof?
This patcher performs assembly-level heuristics instead of naive pattern-matching. The patching itself works more/less the same way as in [keylase/nvidia-patch](https://github.com/keylase/nvidia-patch).

#### Which driver versions are supported?
I have tested this patcher against the following versions:

   - 470.74
   - 495.29.05
   - 495.44

It *should* work on previous versions as well. Please don't open-up new issues if you're using ancient drivers, thanks.

#### Windows support?
No.

# Credits
[keylase/nvidia-patch](https://github.com/keylase/nvidia-patch) - this project wouldn't exist if it wasn't for their outstanding reverse-engineering efforts. thanks!