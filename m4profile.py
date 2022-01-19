#!/usr/bin/env python3

"""
This script profiles each part of masked kyber using the st-link ITM + SWO
It requires a bit of setup though.
You need to install openocd (http://openocd.org/getting-openocd/),
                    arm-none-eabi-gdb (https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads),
                    and itm-tools (https://github.com/japaric/itm-tools)
I had to patch itm-tools slightly to make it work with our code. This patched
version is currently hosted at <https://github.com/dsprenkels/itm-tools.git>.

1) Install openocd in case you do not have it yet:
   $ sudo pacman -S openocd
2) Install arm-none-eabi-gdb
   $ sudo pacman -S arm-none-eabi-gdb
3) Install the patched itm-tools
   $ cargo install --git https://github.com/dsprenkels/itm-tools.git --rev cb9f4a9 
4) Profit (this script should work now)

The following explains how all this works and can be safely ignored.

The general idea is the following: Every x clock cycles you sample the current
value of the PC and send it to the host which can then compute how much time
you spent in each function.

It is based on a recent blog post I came across [1], but I tailored it to our
Dilithium on Cortex-M3 project.

For simplicity let us assume that you have a program that runs the code you
want to profile continuously.
Make sure that there is no UART going on in there, otherwise you will mostly
profile that.
In one terminal start the gdb server:
openocd -f stm32f4discovery.cfg

In another terminal run gdb:
arm-none-eabi-gdb some_elf.elf

In the gdb session do the following (see [1] for details what is actually going on here):

target remote :3333
mon reset halt
load
monitor tpiu config internal itm.fifo uart off 168000000
monitor mmw 0xE0001000 0x1207 0x103FF
monitor itm port 0 on
continue

Note that 168000000 is the frequency your core is running at.
If you are running at 24MHz, you need to change it to 24000000:
monitor tpiu config internal itm.fifo uart off 24000000

Now it should be running and produce tons of binary data in itm.fifo.
Let it run until you think you have enough profiling information.

The next step is to interpret that profiling trace.
For that we can use itm-tools [2] (I have used version e94155e):
It allows you to dump a profiling trace:
$ itm-decode itm.fifo

It will look something like:
PeriodicPcSample { pc: Some(134236526) }
PeriodicPcSample { pc: Some(134233976) }
PeriodicPcSample { pc: Some(134233960) }
PeriodicPcSample { pc: Some(134233976) }
PeriodicPcSample { pc: Some(134234466) }
PeriodicPcSample { pc: Some(134234474) }
PeriodicPcSample { pc: Some(134234478) }
PeriodicPcSample { pc: Some(134234482) }
PeriodicPcSample { pc: Some(134226890) }
PeriodicPcSample { pc: Some(134227486) }
...

The numbers you see (e.g., 134236526 = 0x800496e) are the values you PC had
at a certain point in time. By now looking at the objdump of your elf, you
can figure out in which function it was. Luckily there is tooling for that.

pcsampl maps the PC values back to function names in your symbol table of the elf:
$ pcsampl itm.fifo -e some_elf.elf

This should give you something like: 
    % FUNCTION
 0.00 *SLEEP*
57.18 KeccakF1600_StatePermute
10.44 inv_ntt_asm
 8.62 ntt_asm
 3.43 pqcrystals_dilithium_poly_uniform
 ...

I ran into two problem when using assembly functions:

(1) When a function does not have .type f, %function, it is not listed as
    a function in the symbol table. Keccak does this for example.
    Really this is a bug in the assembly code, and should be fixed there, but
    we decided to work around that issue.
(2) All my assembly functions seem to have size 0 in the symbol table. I do not
    quite know if there is an easy way to fix this when building the elf.

Both meant that itm-tools throws a lot of "Bogus PC" errors, and more
importantly: The assembly functions are never actually taken into account.

I fixed that by patching itm-tools to ignore it and simply assuming that
whenever we hit a bogus PC value, we simply assume that the previous public
label was the function. We put the patched version of itm-tools up on
Github.

For some boards SWO is not enabled by default, so you might have to bridge a
solder bridge. For the STM32F407 Discovery board, this is SB12, which is
enabled by default.

[1] https://interrupt.memfault.com/blog/profiling-firmware-on-cortex-m
"""

import functools
import os
import subprocess
import sys

eprint = functools.partial(print, file=sys.stderr)


def cleanup():
    subprocess.check_call("make clean", shell=True)
    for f in ["keygen.profile", "encaps.profile", "decaps.profile"]:
        if os.path.exists(f):
            os.remove(f)


def profile(scheme):
    cleanup()
    elf = f"elf/{scheme}_profile.elf"
    make = f"make IMPLEMENTATION_PATH=crypto_kem/kyber768/m4 {elf}"
    subprocess.check_call(make, shell=True)

    gdbcmd = f"arm-none-eabi-gdb --batch --command profile_gdbcmds.txt {elf}"
    subprocess.check_call(gdbcmd, shell=True)

    with open(f"{scheme}.profile", "w") as f:
        for profilefile in ["keygen.profile", "encaps.profile", "decaps.profile"]:
            pcsample = f"pcsampl {profilefile} -e {elf}"
            dump = subprocess.check_output(
                pcsample, shell=True, stderr=subprocess.DEVNULL)
            dump = dump.decode()
            dump = "    % FUNCTION"+dump.split("    % FUNCTION")[-1]
            eprint(profilefile, file=f)
            eprint(dump, file=f)
            eprint(profilefile)
            eprint(dump)
    cleanup()


eprint("starting openocd")
openocd_proc = subprocess.Popen(['openocd', '-f', 'stm32f4discovery.cfg'],
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)

profile("crypto_kem_kyber768_m4")

eprint("killing openocd")
openocd_proc.kill()
eprint("done.",)
