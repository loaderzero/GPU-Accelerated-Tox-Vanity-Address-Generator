# GPU-Accelerated-Tox-Vanity-Address-Generator
This is a high-performance tool for generating custom vanity addresses using GPU acceleration via OpenCL. It is a heavily modified and enhanced version of a CPU-based generator, featuring a custom OpenCL kernel for massive parallelization.
## Features

- **GPU Acceleration:** Uses OpenCL to leverage the power of modern GPUs for significantly faster address generation compared to CPU-only methods.
- **Multi-threaded CPU Mode:** Can utilize multiple CPU cores for generation if a compatible GPU is not available.
- **Hybrid Mode:** Capable of running on both CPU and GPU simultaneously to maximize hashing power.
- **Based on proven cryptographic implementations** for key generation and scalar multiplication on Curve25519.

---

## ⚠️ WARNING: Unstable Software ⚠️

This tool is experimental and can be unstable. The OpenCL kernel is designed to push your GPU to its limits.

- **High GPU Load:** Expect 100% GPU utilization. This will increase its temperature and power consumption.
- **System Freezes:** On some hardware/driver combinations, running the kernel may cause system-wide freezes or display driver crashes, requiring a hard reboot.
- **USE AT YOUR OWN RISK.** It is recommended to save all your work before running this tool.

---

## Prerequisites & Dependencies

You need a working C toolchain, the Tox and libsodium libraries, and an OpenCL runtime. The exact packages depend on your operating system.

### Linux

1. **Build tools:** `gcc` (or `clang`) and `make`.
2. **Tox & libsodium development headers:** `libtoxcore-dev`, `libsodium-dev`, or their distribution-specific equivalents.
3. **OpenCL runtime:**
   - **OpenCL headers & ICD loader:** `opencl-headers` and `ocl-icd` (or your distro's meta-package).
   - **GPU driver/runtime:** install the vendor runtime that exposes OpenCL for your card.
     - **AMD:** Mesa's `rusticl` implementation ships with recent Mesa packages.
     - **NVIDIA:** proprietary driver (e.g. `nvidia-opencl-icd` on Debian/Ubuntu).
     - **Intel:** `intel-compute-runtime` or `beignet` depending on GPU generation.

**Arch / EndeavourOS**
```bash
sudo pacman -S gcc make libsodium toxcore opencl-headers ocl-icd mesa
```

**Debian / Ubuntu**
```bash
sudo apt-get install build-essential libsodium-dev libtoxcore-dev ocl-icd-opencl-dev opencl-headers
# Install the matching OpenCL runtime for your GPU (e.g. nvidia-opencl-icd, intel-opencl-icd).
```

### Windows

There are two supported environments:

1. **MSYS2 / MinGW-w64 (recommended for GCC users)**
   - Install [MSYS2](https://www.msys2.org/).
   - Open the "MSYS2 MinGW 64-bit" shell and install packages:
     ```bash
     pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-make \
         mingw-w64-x86_64-libsodium mingw-w64-x86_64-libtoxcore \
         mingw-w64-x86_64-opencl-icd
     ```
   - Install the GPU vendor's OpenCL driver (NVIDIA/AMD/Intel) if it is not already present.

2. **Visual Studio + vcpkg (for MSVC users)**
   - Install [Visual Studio](https://visualstudio.microsoft.com/) with the "Desktop development with C++" workload.
   - Install [vcpkg](https://github.com/microsoft/vcpkg) and integrate it with Visual Studio (`vcpkg integrate install`).
   - Use vcpkg to install dependencies:
     ```powershell
     vcpkg install libsodium:x64-windows libtoxcore:x64-windows opencl:x64-windows
     ```
   - Ensure the GPU's OpenCL runtime is installed (typically bundled with the vendor driver).

If you use MSYS2, the provided `makefile` will build the project directly. For MSVC users, open a "x64 Native Tools" command prompt, run `nmake /f makefile`, or create a new Visual Studio project that compiles `tox.c` with the same dependencies.

### Verifying your OpenCL Setup

Before compiling, make sure your system correctly detects your GPU. You can use a tool like `clinfo`:
```
# Install clinfo (e.g., sudo pacman -S clinfo)
clinfo
```
On Windows you can install [GPU Caps Viewer](https://www.ozone3d.net/gpu_caps_viewer/) or use the GPU vendor's diagnostic utility to check that OpenCL devices are visible. If your GPU does not appear, fix the driver/runtime installation before continuing.

---

## Building

Compiling is straightforward with the provided `Makefile`. Just run:

```
make
```

This will create an executable file named `tox_vanity_miner`.

---

## Usage

Run the program from your terminal. The only required argument is the address prefix you want.

```
./tox_vanity_miner -a <PREFIX> [OPTIONS]
```

**Options:**

| Flag | Argument | Description |
|---|---|---|
| `-a`, `--address` | `<prefix>` | **(Required)** The desired vanity address prefix (e.g., "DEADBEEF"). |
| `-m`, `--mode` | `<cpu\|gpu\|hybrid>` | Operation mode. Defaults to `hybrid`. |
| `-t`, `--threads` | `<num>` | Number of CPU threads to use. Defaults to all available cores. |
| `-n`, `--nospam` | `<value>` | Nospam value in integer or hex (e.g., `1234` or `0xCAFE`). Defaults to `0`. |
| `-v`, `--version` | | Show version information. |
| `-h`, `--help` | | Print this help message. |

**Examples:**

- **Use GPU only:**
  ```
  ./tox_vanity_miner -a CAKE -m gpu
  ```

- **Use 4 CPU threads only:**
  ```
  ./tox_vanity_miner -a CAKE -m cpu -t 4
  ```

---

## License

This project is licensed under the **GNU General Public License v2.0**, as it is a derivative work of a GPL-2.0 licensed project. See the [LICENSE](LICENSE) file for more details.

## Credits & Attribution

- The base for the C host program (`tox.c`) was adapted from [zoff99/ToxVanityAddressgenerator](https://github.com/zoff99/ToxVanityAddressgenerator).
- The low-level cryptographic math in the OpenCL kernel (`vanity_kernel.cl`) is based on highly optimized implementations found in projects like Monero, adapted for this specific use case.
