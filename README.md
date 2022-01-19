# First-Order Masked Kyber on ARM Cortex-M4
This is the repository for the first-order masked Kyber on ARM Cortex-M4 [ePrint](https://eprint.iacr.org/2022/058)

# Setup/Installation

First setup the same tools (STLink, ARM Toolchain, OpenOCD) as in the [pqm4](https://github.com/mupq/pqm4) project with the STM32F4 Discovery board.

```sh
# Build the firmware if you haven't already
make clean
make IMPLEMENTATION_PATH=crypto_kem/kyber768/m4 "$target"
```

## Using Visual Studio Code

- Install the Corte-Debug extension (`marus25.cortex-debug`).
- Build the firmware
- Run the "OpenOCD" debug config

## Doing it manually

```sh
target="elf/crypto_kem_kyber768_m4_test.elf"

make clean
make IMPLEMENTATION_PATH=crypto_kem/kyber768/m4 "$target"

# In a separate terminal, start openocd using:
openocd --file stm32f4discovery.cfg

# Start GDB
arm-none-eabi-gdb -q -x openocd.gdb "$target"
```
