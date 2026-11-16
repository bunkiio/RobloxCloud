#!/usr/bin/env python3
"""
Debug version - verify breakpoint addresses contain valid code,
then try to hit them.
"""
import subprocess
import os
import time

def sh(cmd, timeout=120):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()

print("=== ROBLOX CAPTURE (debug) ===", flush=True)

# find cordial-run process
rc, out = sh("pgrep -f cordial-run")
pids = [p for p in out.strip().split('\n') if p.strip()]
print(f"Found PIDs: {pids}", flush=True)

if not pids:
    print("ERROR: cordial-run not running", flush=True)
    exit(1)

pid = None
for p in pids:
    rc, out = sh(f"grep -l libroblox /proc/{p}/maps 2>/dev/null")
    if rc == 0:
        pid = p
        break

if not pid:
    print("ERROR: no process has libroblox.so loaded", flush=True)
    exit(1)

print(f"Using PID: {pid}", flush=True)

rc, out = sh(f"grep 'libroblox.so' /proc/{pid}/maps | head -1")
print(f"Maps line: {out}", flush=True)

base_hex = out.split('-')[0]
BASE = int(base_hex, 16)
print(f"BASE = {hex(BASE)}", flush=True)

os.makedirs("/tmp/cap746", exist_ok=True)

# our target offsets
BLOB_OFF = 0x427a7d4
A7_OFF = 0x6152814

BLOB_ADDR = BASE + BLOB_OFF
A7_ADDR = BASE + A7_OFF

print(f"Blob decoder @ {hex(BLOB_ADDR)} (offset {hex(BLOB_OFF)})", flush=True)
print(f"A7 builder @ {hex(A7_ADDR)} (offset {hex(A7_OFF)})", flush=True)

# first: just peek at those addresses to see if they contain code
debug_gdb = f'''set pagination off
set confirm off

# dump bytes at our target addresses
printf "\\n=== CHECKING BLOB DECODER @ {hex(BLOB_ADDR)} ===\\n"
x/16i {hex(BLOB_ADDR)}

printf "\\n=== CHECKING A7 BUILDER @ {hex(A7_ADDR)} ===\\n"
x/16i {hex(A7_ADDR)}

# also let's find where the packet dispatcher is - look for 0x9b handler
# search for patterns that might be hit more frequently
printf "\\n=== CHECKING PACKET DISPATCH AREA ===\\n"
# the dispatch table remap is at 0x763a58
set $remap = {hex(BASE + 0x763a58)}
printf "Remap table @ %p\\n", $remap
x/16bx $remap

printf "\\n=== SETTING BREAKPOINTS ===\\n"
break *{hex(BLOB_ADDR)}
info breakpoints

printf "\\nNow continuing for 20 seconds...\\n"
continue &
shell sleep 20
interrupt
info breakpoints
detach
quit
'''

open("/tmp/capture.gdb", "w").write(debug_gdb)
print("GDB script written (debug mode)", flush=True)

open("/tmp/cap746/started.txt", "w").write(f"started at {time.time()}\n")

print("Attaching gdb to inspect code at breakpoint addresses...", flush=True)

cmd = f"timeout 35 gdb -batch -n -p {pid} -x /tmp/capture.gdb 2>&1"
print(f"CMD: {cmd}", flush=True)

rc, out = sh(cmd, timeout=40)
print(f"GDB exit code: {rc}", flush=True)
print("--- GDB OUTPUT ---", flush=True)
print(out, flush=True)
print("--- END GDB OUTPUT ---", flush=True)
