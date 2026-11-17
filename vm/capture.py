#!/usr/bin/env python3
"""
Capture 0x90 packet from 746 Roblox client using GDB.
Based on prasoet-cmu's Boblox capture scripts.

The Frida approach failed - GDB is more reliable for this.
"""
import subprocess
import os
import sys
import time
import glob
import tempfile

def sh(cmd, timeout=120):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()

print("=== ROBLOX 746 0x90 CAPTURE (GDB) ===", flush=True)

CAP_DIR = "/tmp/cap746"
os.makedirs(CAP_DIR, exist_ok=True)

# Check for existing results
results = glob.glob(f"{CAP_DIR}/*_op90_*.bin")
if results:
    print("=== EXISTING CAPTURE RESULTS ===", flush=True)
    for fpath in sorted(results):
        with open(fpath, "rb") as f:
            data = f.read()
        fname = os.path.basename(fpath)
        print(f"{fname}: {len(data)} bytes", flush=True)
        print(f"  First 64: {data[:64].hex()}", flush=True)
        if len(data) > 2 and data[0] == 0x90:
            print(f"  ✓ Valid 0x90 header", flush=True)
    print("", flush=True)
    print("To restart: rm -rf /tmp/cap746", flush=True)
    sys.exit(0)

# Check if capture is running
rc, out = sh("pgrep -f 'gdb.*capture_90.gdb'")
if rc == 0:
    print("GDB capture already running, pid:", out, flush=True)
    if os.path.exists(f"{CAP_DIR}/index.txt"):
        print("", flush=True)
        print("=== CAPTURE LOG ===", flush=True)
        print(open(f"{CAP_DIR}/index.txt").read()[-2000:], flush=True)
    print("", flush=True)
    print("Waiting for 0x90... join a game!", flush=True)
    sys.exit(0)

# Find the Roblox process
print("Finding Roblox process...", flush=True)

rc, out = sh("pgrep -f 'cordial-run'")
if rc != 0:
    rc, out = sh("pgrep -f 'libroblox'")
if rc != 0:
    print("ERROR: No Roblox process found", flush=True)
    print("Start Roblox first, then run capture", flush=True)
    sys.exit(1)

pids = [p.strip() for p in out.split('\n') if p.strip()]
print(f"Found pids: {pids}", flush=True)

# Find the one with libroblox.so loaded
target_pid = None
libroblox_base = None

for pid in pids:
    rc, maps = sh(f"cat /proc/{pid}/maps 2>/dev/null | grep -i libroblox | head -1")
    if rc == 0 and maps and 'libroblox' in maps.lower():
        target_pid = pid
        # Parse base address (first field before the dash)
        base_hex = maps.split('-')[0]
        libroblox_base = int(base_hex, 16)
        print(f"Found libroblox in pid {pid}", flush=True)
        print(f"  Map line: {maps[:100]}", flush=True)
        print(f"  Base: {hex(libroblox_base)}", flush=True)
        break

if not target_pid:
    print("ERROR: No process has libroblox.so loaded", flush=True)
    sys.exit(1)

# The send function offset.
# 739: 0x631BD58  ->  746: 0x301E650 (found via string-anchor scan, cross-checked
# by identical prologue + 'ctrl' constant + matching ns struct offsets).
SEND_OFFSET = 0x301E650

print(f"", flush=True)
print(f"Target: pid={target_pid}, libroblox base={hex(libroblox_base)}", flush=True)
print(f"Send function offset: {hex(SEND_OFFSET)} (746)", flush=True)
print(f"Breakpoint will be at: {hex(libroblox_base + SEND_OFFSET)}", flush=True)

# Write the GDB script
gdb_script = f'''# Auto-generated capture script
set pagination off
set confirm off

python
import gdb, os

CAP_DIR = "{CAP_DIR}"
os.makedirs(CAP_DIR, exist_ok=True)
LOG = open(os.path.join(CAP_DIR, "index.txt"), "a", buffering=1)

def u8(a):
    return int.from_bytes(gdb.selected_inferior().read_memory(a, 1).tobytes(), "little")

def u64(a):
    return int.from_bytes(gdb.selected_inferior().read_memory(a, 8).tobytes(), "little")

BASE = {hex(libroblox_base)}
SEND_ADDR = BASE + {hex(SEND_OFFSET)}
print(f"libroblox BASE={{hex(BASE)}}")
print(f"Breakpoint at {{hex(SEND_ADDR)}}")

COUNTER = {{"n": 0}}
GOT_90 = {{"v": False}}

class SendBp(gdb.Breakpoint):
    """Capture packets. app=rdx&0xFF, chan=rcx, ns=r8"""
    def stop(self):
        try:
            rdx, rcx, r8 = (int(gdb.parse_and_eval(r)) for r in ("$rdx", "$rcx", "$r8"))
            app = rdx & 0xFF
            chan = rcx & 0xFFFFFFFF
            
            # app=4 chan=1 is the reliable game channel
            if app != 4 or chan != 1:
                return False
            
            ns = r8
            flag = u8(ns + 64)
            if flag:
                data_ptr = u64(ns + 32)
                length = u64(ns + 40)
            else:
                data_ptr = u64(ns + 8)
                length = u64(ns + 16) - data_ptr
            consumed = u64(ns + 72)
            begin = data_ptr + consumed
            size = length - consumed if length >= consumed else 0
            
            if not (0 < size < 66000):
                return False
            
            payload = gdb.selected_inferior().read_memory(begin, size).tobytes()
            opcode = payload[0] if payload else 0
            
            idx = COUNTER["n"]
            COUNTER["n"] += 1
            
            fn = os.path.join(CAP_DIR, f"msg_{{idx:04d}}_op{{opcode:02x}}_sz{{size}}.bin")
            open(fn, "wb").write(payload)
            
            LOG.write(f"{{idx:04d}} opcode=0x{{opcode:02x}} size={{size}} -> {{fn}}\\n")
            LOG.flush()
            
            print(f"CAPTURED: opcode=0x{{opcode:02x}} size={{size}}")
            
            if opcode == 0x90:
                print(f"*** GOT 0x90! size={{size}} ***")
                GOT_90["v"] = True
                # Write marker file
                open(os.path.join(CAP_DIR, "GOT_90"), "w").write(fn)
                
        except Exception as e:
            LOG.write(f"ERR {{e}}\\n")
            print(f"ERROR: {{e}}")
        return False

SendBp(f"*{{SEND_ADDR}}", internal=False)
print("Breakpoint set. Waiting for packets...")
print(f"Output dir: {{CAP_DIR}}")
LOG.write("=== GDB capture started ===\\n")
LOG.flush()
end

continue
'''

script_path = f"{CAP_DIR}/capture_90.gdb"
with open(script_path, "w") as f:
    f.write(gdb_script)

print("", flush=True)
print("Starting GDB capture...", flush=True)

# Run GDB in background
log_path = f"{CAP_DIR}/gdb.log"
cmd = f"nohup timeout 300 gdb -p {target_pid} -x {script_path} -batch > {log_path} 2>&1 &"
os.system(cmd)

time.sleep(3)

# Check if it started
if os.path.exists(log_path):
    log = open(log_path).read()
    print("=== GDB OUTPUT ===", flush=True)
    print(log[:1500] if len(log) > 1500 else log, flush=True)
    
    if "Breakpoint set" in log:
        print("", flush=True)
        print("✓ GDB attached and breakpoint set!", flush=True)
        print("", flush=True)
        print("NOW JOIN A GAME!", flush=True)
        print("The 0x90 packet is sent early in the join sequence.", flush=True)
        print("", flush=True)
        print("Run this again to check for captured packets.", flush=True)
    elif "Cannot attach" in log or "ptrace" in log:
        print("", flush=True)
        print("ERROR: GDB cannot attach (ptrace blocked)", flush=True)
        print("Try: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope", flush=True)
    elif "No symbol" in log or "Cannot insert breakpoint" in log:
        print("", flush=True)
        print("ERROR: Breakpoint failed - offset may be wrong for 746", flush=True)
        print("The 739 offset 0x631BD58 may not work on 746.", flush=True)
else:
    print("ERROR: GDB did not start", flush=True)
