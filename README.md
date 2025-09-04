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

This program is intended for **Linux** systems. It has been tested on Arch-based distributions (EndeavourOS).

You will need the following dependencies installed (development headers are required):

1.  **A C Compiler & Build Tools:** `gcc` and `make`.
2.  **libsodium-dev:** For cryptographic helper functions.
3.  **libtoxcore-dev:** The core Tox library.
4.  **OpenCL:**
    *   **OpenCL Headers & ICD Loader:** `opencl-headers` and `ocl-icd`.
    *   **GPU Drivers:** You need the correct OpenCL driver for your GPU.
        - **AMD:** `mesa` drivers usually include the `rusticl` OpenCL implementation.
        - **NVIDIA:** The proprietary NVIDIA drivers are required.
        - **Intel:** The `intel-compute-runtime` is typically needed.

**Installation Example (Arch Linux / EndeavourOS):**
```
sudo pacman -S gcc make libsodium toxcore opencl-headers ocl-icd mesa
```

**Installation Example (Debian / Ubuntu):**
```
sudo apt-get install build-essential libsodium-dev libtoxcore-dev ocl-icd-opencl-dev opencl-headers
# You will also need to install the correct GPU drivers and OpenCL runtime for your hardware.
```

### Verifying your OpenCL Setup

Before compiling, make sure your system correctly detects your GPU. You can use a tool like `clinfo`:
```
# Install clinfo (e.g., sudo pacman -S clinfo)
clinfo
```
If the output shows your GPU and its platforms, you are ready to proceed. If not, you need to fix your OpenCL driver installation.

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
