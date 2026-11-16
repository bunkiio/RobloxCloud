#!/usr/bin/env python3
import subprocess
import os
import time

def sh(cmd, timeout=120):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()

print("=== ROBLOX CAPTURE ===", flush=True)

# find cordial-run process (that's where libroblox.so is loaded)
rc, out = sh("pgrep -f cordial-run")
pid = out.strip().split('\n')[0] if out.strip() else None

if not pid:
    print("ERROR: cordial-run not running", flush=True)
    exit(1)

print(f"Found cordial-run PID: {pid}", flush=True)

# verify libroblox.so is loaded
rc, out = sh(f"grep libroblox /proc/{pid}/maps | head -1")
if "libroblox" not in out:
    print("ERROR: libroblox.so not loaded in process", flush=True)
    exit(1)

print("libroblox.so confirmed in process", flush=True)

# create output directory
os.makedirs("/tmp/cap746", exist_ok=True)

# write gdb capture script
capture_gdb = '''
set pagination off
set confirm off

python
import gdb, os, time

RUN = "/tmp/cap746"
os.makedirs(RUN, exist_ok=True)
LOG = open(os.path.join(RUN, "index.txt"), "a", buffering=1)
T0 = time.monotonic()

def u8(a): return int.from_bytes(gdb.selected_inferior().read_memory(a, 1).tobytes(), "little")
def u64(a): return int.from_bytes(gdb.selected_inferior().read_memory(a, 8).tobytes(), "little")
def rd(a, n):
    try:
        return gdb.selected_inferior().read_memory(a, n).tobytes()
    except:
        return b""

pid = gdb.selected_inferior().pid
BASE = None
for line in open(f"/proc/{pid}/maps"):
    if "libroblox.so" in line and line.split()[2] == "00000000":
        BASE = int(line.split("-")[0], 16)
        break

if BASE is None:
    print("ERROR: no libroblox base")
    LOG.write("ERROR: no base\\n")
    gdb.execute("quit")

LOG.write(f"# BASE={hex(BASE)} pid={pid}\\n")
LOG.flush()
print(f"BASE={hex(BASE)}")

CNT = {"chal": 0, "a7": 0}
DEADLINE = T0 + 120

def maybe_quit():
    if time.monotonic() > DEADLINE:
        LOG.write("# deadline\\n")
        gdb.execute("detach")
        gdb.execute("quit")

class BlobBp(gdb.Breakpoint):
    def stop(self):
        try:
            rsi = int(gdb.parse_and_eval("$rsi"))
            flag = u8(rsi)
            if flag & 1:
                ptr, ln = u64(rsi+16), u64(rsi+8)
            else:
                ln, ptr = flag>>1, rsi+1
            if 0 < ln < 100000 and 0x1000 < ptr:
                blob = rd(ptr, ln)
                idx = CNT["chal"]; CNT["chal"] += 1
                open(f"{RUN}/chal_{idx:04d}.bin", "wb").write(blob)
                LOG.write(f"CHAL {idx} {ln}B\\n")
                LOG.flush()
                print(f"[CHAL] {ln}B")
        except Exception as e:
            LOG.write(f"ERR {e}\\n")
        maybe_quit()
        return False

class A7Bp(gdb.Breakpoint):
    def stop(self):
        try:
            rdi = int(gdb.parse_and_eval("$rdi"))
            idx = CNT["a7"]; CNT["a7"] += 1
            if 0x1000 < rdi < 0x800000000000:
                ctx = rd(rdi, 512)
                open(f"{RUN}/a7_{idx:04d}.bin", "wb").write(ctx)
                LOG.write(f"A7 {idx}\\n")
                LOG.flush()
                print(f"[A7] captured")
        except Exception as e:
            LOG.write(f"ERR {e}\\n")
        maybe_quit()
        return False

BlobBp(f"*{BASE + 0x427a7d4}")
print(f"Blob bp @ {hex(BASE + 0x427a7d4)}")

A7Bp(f"*{BASE + 0x6152814}")
print(f"A7 bp @ {hex(BASE + 0x6152814)}")

LOG.write("# ready\\n")
print("Capture ready - play the game!")
end

continue
'''

open("/tmp/capture.gdb", "w").write(capture_gdb)
print("GDB script written", flush=True)

print("Attaching gdb (2 min timeout)...", flush=True)
rc, out = sh(f"timeout 130 gdb -p {pid} -x /tmp/capture.gdb 2>&1", timeout=140)
print(out[-3000:], flush=True)

print("\n=== RESULTS ===", flush=True)
rc, out = sh("ls -la /tmp/cap746/")
print(out, flush=True)

rc, out = sh("cat /tmp/cap746/index.txt 2>/dev/null || echo 'no log'")
print(f"Log: {out}", flush=True)
