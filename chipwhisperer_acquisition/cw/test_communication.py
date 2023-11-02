import chipwhisperer as cw
import time
import subprocess

PLATFORM = 'CWLITEARM'


# convert an integer to a hex string for communication
def hex_str(num):
    return " ".join(["%02x" % ((num >> (8 * i)) & 0xff) for i in range(15, -1, -1)])

# run bash command and return output
def run_cmd(cmd):
    return subprocess.check_output(cmd, shell=True).decode('utf-8')

cmd_make1 = "make clean PLATFORM={}".format(PLATFORM)
cmd_make2 = "make PLATFORM='CW308_STM32F4' CRYPTO_TARGET=NONE"
cmd_make3 = "mkdir objdir; cd objdir; mkdir crypto_kem; cd crypto_kem; mkdir kyber768; cd kyber768; mkdir m4; cd ../..; mkdir common; cd ..; make PLATFORM={}".format(PLATFORM)

# compile the firmware
print(run_cmd(cmd_make1))
print(run_cmd(cmd_make2))
print(run_cmd(cmd_make3))


# CONNECT THE DEVICE AND FIND NUMSAMPLES AND DOWNSAMPLING RATE:
scope = cw.scope()
scope.default_setup()
target = cw.target(scope, cw.targets.SimpleSerial)

# setup scope parameters
scope.gain.db = 25
scope.adc.samples = 24400
scope.adc.offset = 0
scope.adc.decimate = 200
scope.adc.basic_mode = "rising_edge"
scope.adc.timeout = 2
scope.clock.clkgen_freq = 7370000
scope.clock.adc_src = "clkgen_x4"
scope.trigger.triggers = "tio4"
scope.io.tio1 = "serial_rx"
scope.io.tio2 = "serial_tx"
scope.io.hs2 = "clkgen"

# set the amount of communicated data like this => target.output_len = 4

prog = cw.programmers.STM32FProgrammer
fw_path = './simpleserial-masked-kyber-{}.hex'.format(PLATFORM)

cw.program_target(scope, prog, fw_path)

time.sleep(2)

ktp = cw.ktp.Basic()  # object to generate fixed/random key and text (default fixed key, random text)
ktp.fixed_text = True
ktp.fixed_key = True
key, text = ktp.next()  # get our key and text

ret = cw.capture_trace(scope, target, text, key)


scope.adc.decimate = round(scope.adc.trig_count / 24400 + 0.5)
numPoints = round(scope.adc.trig_count / scope.adc.decimate)

scope.adc.samples = numPoints


hex_10000 = 0x10000
test_data = [1,2,3,4,5,6,7,8]
coefs_int = 0
tmp = test_data[::-1]
for i in range(0, len(test_data)):
    coefs_int += tmp[i] * hex_10000 ** i

coefs_str = hex_str(coefs_int)


start_time = time.time()
ktp.setInitialText(coefs_str)   # set the value to be returned by the first call to ktp.next()

key, text = ktp.next()  # manual creation of a key, text pair can be substituted here
print("TEXT IN : ", text.hex())
target.simpleserial_write('p', text)


ret = cw.capture_trace(scope, target, text, key)
print("TEXT OUT: ", ret.textout.hex())
end_time = time.time()
print("Time elapsed: " + str(round(end_time - start_time, 2)) + " s")






