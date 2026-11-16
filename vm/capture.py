#!/usr/bin/env python3
"""
Single-shot capture — hit each breakpoint once, grab data, detach.
Minimizes pause time to avoid Cloudflare 524 timeout.
"""
import subprocess
import os
import time

def sh(cmd, timeout=120):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()

print("=== ROBLOX CAPTURE (single-shot) ===", flush=True)

# find cordial-run process (that's where libroblox.so is loaded)
rc, out = sh("pgrep -f cordial-run")
pids = [p for p in out.strip().split('\n') if p.strip()]
print(f"Found PIDs: {pids}", flush=True)

if not pids:
    print("ERROR: cordial-run not running", flush=True)
    exit(1)

# find the one with libroblox.so loaded
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

# get the base address directly
rc, out = sh(f"grep 'libroblox.so' /proc/{pid}/maps | head -1")
print(f"Maps line: {out}", flush=True)

if not out:
    print("ERROR: can't read maps", flush=True)
    exit(1)

# parse base address from maps line
base_hex = out.split('-')[0]
BASE = int(base_hex, 16)
print(f"BASE = {hex(BASE)}", flush=True)

# create output directory
os.makedirs("/tmp/cap746", exist_ok=True)

# calculate addresses
BLOB_ADDR = BASE + 0x427a7d4
A7_ADDR = BASE + 0x6152814

print(f"Blob decoder @ {hex(BLOB_ADDR)}", flush=True)
print(f"A7 builder @ {hex(A7_ADDR)}", flush=True)

# single-shot gdb script: hit breakpoint, grab data, delete breakpoint, continue
# after both are captured (or timeout), detach cleanly
capture_gdb = f'''set pagination off
set confirm off
set breakpoint pending on

# use python to track what we've captured
python
got_chal = False
got_a7 = False
end

# breakpoint 1: challenge blob decoder
break *{hex(BLOB_ADDR)}
commands 1
silent
python
import gdb, os
global got_chal
if not got_chal:
    RUN = "/tmp/cap746"
    rsi = int(gdb.parse_and_eval("$rsi"))
    try:
        flag = int.from_bytes(gdb.selected_inferior().read_memory(rsi, 1).tobytes(), "little")
        if flag & 1:
            ptr = int.from_bytes(gdb.selected_inferior().read_memory(rsi+16, 8).tobytes(), "little")
            ln = int.from_bytes(gdb.selected_inferior().read_memory(rsi+8, 8).tobytes(), "little")
        else:
            ln = flag >> 1
            ptr = rsi + 1
        if 0 < ln < 100000:
            blob = gdb.selected_inferior().read_memory(ptr, ln).tobytes()
            open(f"{{RUN}}/challenge.bin", "wb").write(blob)
            print(f"[CHAL] captured {{ln}} bytes")
            got_chal = True
    except Exception as e:
        print(f"[CHAL ERR] {{e}}")
end
# delete this breakpoint so we don't hit it again
delete 1
continue
end

# breakpoint 2: A7 builder
break *{hex(A7_ADDR)}
commands 2
silent
python
import gdb, os
global got_a7
if not got_a7:
    RUN = "/tmp/cap746"
    rdi = int(gdb.parse_and_eval("$rdi"))
    try:
        if 0x1000 < rdi < 0x800000000000:
            # grab more context - the whole builder state
            ctx = gdb.selected_inferior().read_memory(rdi, 1024).tobytes()
            open(f"{{RUN}}/a7_context.bin", "wb").write(ctx)
            # also dump some stack context
            rsp = int(gdb.parse_and_eval("$rsp"))
            stk = gdb.selected_inferior().read_memory(rsp, 512).tobytes()
            open(f"{{RUN}}/a7_stack.bin", "wb").write(stk)
            print("[A7] captured context + stack")
            got_a7 = True
    except Exception as e:
        print(f"[A7 ERR] {{e}}")
end
# delete this breakpoint
delete 2
continue
end

# set a watchdog: after 30 seconds, detach no matter what
python
import threading, time
def watchdog():
    time.sleep(30)
    print("[WATCHDOG] 30s elapsed, detaching")
    try:
        gdb.execute("detach", to_string=True)
        gdb.execute("quit", to_string=True)
    except:
        pass
t = threading.Thread(target=watchdog, daemon=True)
t.start()
end

continue
'''

open("/tmp/capture.gdb", "w").write(capture_gdb)
print("GDB script written (single-shot mode)", flush=True)

# write start marker
open("/tmp/cap746/started.txt", "w").write(f"started at {time.time()}\n")

print("Attaching gdb (will detach after captures or 30s)...", flush=True)

# run gdb - timeout at 45s (watchdog is 30s)
cmd = f"timeout 45 gdb -batch -n -p {pid} -x /tmp/capture.gdb 2>&1"
print(f"CMD: {cmd}", flush=True)

rc, out = sh(cmd, timeout=50)
print(f"GDB exit code: {rc}", flush=True)
# show last part of output
lines = out.split('\n')
print('\n'.join(lines[-30:]) if len(lines) > 30 else out, flush=True)

print("\n=== CAPTURED FILES ===", flush=True)
rc, out = sh("ls -la /tmp/cap746/")
print(out, flush=True)

# show file sizes
for fname in ["challenge.bin", "a7_context.bin", "a7_stack.bin"]:
    fpath = f"/tmp/cap746/{fname}"
    if os.path.exists(fpath):
        sz = os.path.getsize(fpath)
        print(f"{fname}: {sz} bytes", flush=True)
        # show hex preview of first 64 bytes
        with open(fpath, "rb") as f:
            data = f.read(64)
        print(f"  preview: {data.hex()}", flush=True)
