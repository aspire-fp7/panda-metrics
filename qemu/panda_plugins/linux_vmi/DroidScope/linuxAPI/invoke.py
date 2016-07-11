#!/usr/bin/python
import subprocess
import sys
import telnetlib

# arm-softmmu/qemu-system-arm -M android_arm -cpu cortex-a9 -kernel Aspire42-qcow/kernel -initrd Aspire42-qcow/initramfs -global goldfish_nand.system_path=Aspire42-qcow/system-pandroid.qcow2 -global goldfish_nand.user_data_path=Aspire42-qcow/data-pandroid.qcow2 -global goldfish_nand.cache_path=Aspire42-qcow/cache-pandroid.qcow2 -append "console=ttyS0 ndns=2 qemu=1 no_console_suspend=1 qemu.gles=0 android.qemud=ttyS1" -m 512M -no-reboot -monitor telnet:localhost:4321,server,nowait -show-cursor -serial stdio -serial telnet:localhost:4421,server,nowait -display sdl -global goldfish_mmc.sd_path=Aspire42-qcow/sdcard.qcow2 -android -S -net nic,vlan=1 -net user,vlan=1

diablodir="/home/aspire/repositories/...../actc/build/liblib/BC05/"
programname="demo"
libraryname="liblib.so"

#replayFile="vanilla-automated-retest"
replayFile="flattenall_more_coverage-automated-retest"

forward_trace_len=1
backward_trace_len=0

local_command_dir = "/home/aspire/repositories/...../demo"
local_command = "./install_programs_android.sh"

listfilename = diablodir + libraryname + ".list"

qemu = "./arm-softmmu/qemu-system-arm"
baseline_args = ["-m", "512M", "-M", "android_arm", "-android", "-cpu", "cortex-a9", "-kernel", "/dev/null", "-global", "goldfish_mmc.sd_path=/dev/null",
                 "-global", "goldfish_nand.system_path=../dummy2.qcow2", "-global", "goldfish_nand.user_data_path=../dummy.qcow2",  "-os", "linux-32-3.2.54" ]

def get_gmrt_and_size(listfilename):
  # '   section .data.gmrt new 0x3ac0b8 old 0x4c80d8 size 10'
  # size is hex
  # new address is really the offset in a library
  for line in open(listfilename, "r"):
    #print line
    if line.startswith("   section .data.gmrt new "):
      s = line.split(" ")
      offset = int(s[6], base=16) # starts with 3 spaces
      size = int(s[10], base=16)

      return offset, size

  return None

def get_offset_of_first_instruction(listfilename):
  #========================[.text]========================
  #New  0x880  Old  0xaad00 MOV        r1,#0x2 (phase: Flowgraph)
  next = False
  for line in open(listfilename, "r"):
    if not next and line.startswith("========================[.text]========================"):
      next = True
    elif next:
      s = line.split(" ")
      return int(s[2], base=16)
  print "Could not determine offset of the first instruction!"
  sys.exit(-1)


def runFullAnalysis():
  gmrt_info = get_gmrt_and_size(listfilename)
  if gmrt_info is not None:
    (gmrt_offset, gmrt_size) = gmrt_info
  else:
    gmrt_offset=0xffffffff
    gmrt_size=0

  offset_of_first_instruction = get_offset_of_first_instruction(listfilename)
  print "OFFSET 0x%x" % offset_of_first_instruction

  vmi_arg = "linux_vmi:gmrt_offset=0x%x,gmrt_size=0x%x,traced_program=%s,library_name=/%s,trace_memory_reuse=1,trace_memory_constness=1,offset_of_first_instruction=0x%x,backward_trace_len=%i,forward_trace_len=%i" % (
    gmrt_offset,
    gmrt_size,
    programname,
    libraryname,
    offset_of_first_instruction,
    backward_trace_len,
    forward_trace_len)

  analysis_args = ["-panda", vmi_arg, "-replay", replayFile]

  while True:
    try:
      with open("pandalog", "w") as pandalog:
        print "Running Panda analysis"
        subprocess.check_call([qemu] + baseline_args + analysis_args, stderr=pandalog)
    except subprocess.CalledProcessError:
        with open("pandalog", "r") as pandalog:
          content = pandalog.readlines()

          print "Bart's invoke.py caught the PANDA error: '%s'..." % content[-1]
          if content[-1] == "NAND: could not create temp file for cache NAND disk image: File exists\n":
            print "... retrying"
          else:
            print "... this is an unknown error, aborting!"
            sys.exit(-1)
    else:
        # try was successful
        break

  print "Analysis done!"

def record():
  monitor = telnetlib.Telnet("localhost", 4321)

  monitor.read_until("(qemu) ")
  monitor.write("begin_record %s\n" % replayFile)

  subprocess.check_call(local_command, cwd=local_command_dir)

  monitor.read_until("(qemu) ")
  monitor.write("end_record\n")
  monitor.read_until("(qemu) ") # So that we know the end_record was processed
  monitor.close()


record()
runFullAnalysis()
