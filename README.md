# Capstone-RISC-V Spike Simulator

The Capstone-RISC-V Spike Simulator is based on the [Spike RISC-V ISA Simulator](https://github.com/riscv-software-src/riscv-isa-sim).

## Implementation

The Capstone-RISC-V Spike Simulator simulates a Capstone-RISC-V processor.

The interface of the processor follows the [Capstone-RISC-V ISA](https://capstone.kisp-lab.org/specs/), and some implementation-defined specifications are provided:

- [Spike simulator's implementation of Capstone-RISC-V]()
- [Spike debugging manual]()
- [Developer's manual]()

## Quick Start

Please refer to the [Capstone-RISC-V Spike Simulator SDK](https://github.com/project-starch/transcapstone-sim).
Both an [Apptainer](https://apptainer.org/) image and a building script are provided.

## Building

1. Build the [RISC-V GNU Toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain/).
2. Build the [RISC-V Proxy Kernel](https://github.com/riscv-software-src/riscv-pk/).
3. Follow the building instructions for the [Spike RISC-V ISA Simulator](https://github.com/riscv-software-src/riscv-isa-sim).
