# Capstone-RISC-V Spike Simulator

The Capstone-RISC-V Spike Simulator is based on the [Spike RISC-V ISA Simulator](https://github.com/riscv-software-src/riscv-isa-sim).

## Docs

The Capstone-RISC-V Spike Simulator simulates a Capstone-RISC-V processor.

The interface of the processor follows the [Capstone-RISC-V ISA](https://capstone.kisp-lab.org/specs/), and some implementation-defined specifications are provided:

- [Spike simulator's implementation of Capstone-RISC-V](docs/spike-impl.adoc)
- [Debugging in Spike](docs/spike-debug.adoc)
- [Capstone-RISC-V Spike developer guide](docs/dev-manual.adoc)

## Quick Start

Please refer to the [Capstone-RISC-V Spike Simulator SDK](https://github.com/project-starch/transcapstone-sim).
Both an [Apptainer](https://apptainer.org/) image and a building script are provided.

## Building

1. Build the [RISC-V GNU Toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain/).
2. Build the [RISC-V Proxy Kernel](https://github.com/riscv-software-src/riscv-pk/).
3. Follow the building instructions for the [Spike RISC-V ISA Simulator](https://github.com/riscv-software-src/riscv-isa-sim).

## Common Options

> Note: some original options of Spike are not supported in Capstone-RISC-V Spike yet. Please be careful when using the options that are not listed here.

| Parameter | Description |
| --- | --- |
| `-h`, `--help` | Print help message |
| `-m<a:m,b:n,...>` | Provide memory regions of size m and n bytes at base addresses a and b (with 4 KiB alignment) |
| `-p<n>` | Simulate n processors (default 1) |
| `--isa=<name>` | RISC-V ISA string (default `RV64IMAFDC`)
| `-M<a:m>` | Provide secure memory regions of size m bytes at base addresses a (with 4 KiB alignment) |
| `-R<n>` | The size of revocation tree (default `1024*1024`) |
| `-D` | Enable debug instructions | RISC-V privilege modes supported (default `msu`) |
| `-P` | Pure Capstone (currently not supported) |
