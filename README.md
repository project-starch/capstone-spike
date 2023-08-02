# Capstone-RISC-V Spike Simulator

The Capstone-RISC-V Spike Simulator is based on the [Spike RISC-V ISA Simulator](https://github.com/riscv-software-src/riscv-isa-sim).

## Implementation

The Capstone-RISC-V Spike Simulator simulates a Capstone-RISC-V processor. The interface of the processor follows the [Capstone-RISC-V ISA](https://capstone.kisp-lab.org/specs/), but there are some implementation-defined specifications.

> **Note: The implementation on this branch follows the interfaces defined in the [USENIX Security '23 paper](https://www.usenix.org/conference/usenixsecurity23/presentation/yu-jason) instead of the latest Capstone-RISC-V ISA.**

> The encodings of the instructions are different from the ones defined in the *Capstone-RISC-V ISA* as well. This branch is only for archiving the implementation defined in the *USENIX Security '23 paper*, and will not be maintained in the future.

## Quick Start

Please refer to the [Capstone-RISC-V Spike Simulator SDK](https://github.com/project-starch/transcapstone-sim).
Both an [Apptainer](https://apptainer.org/) image and a building script are provided.

## Building

1. Build the [RISC-V GNU Toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain/).
2. Build the [RISC-V Proxy Kernel](https://github.com/riscv-software-src/riscv-pk/).
3. Follow the building instructions for the [Spike RISC-V ISA Simulator](https://github.com/riscv-software-src/riscv-isa-sim).
