#!/usr/bin/env python3
import subprocess
import os
import time

def sh(cmd, timeout=60):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()

print("=== ROBLOX CAPTURE ===")

rc, out = sh("pgrep -f libroblox")
pid = out.strip().split('\n')[0] if out.strip() else None

if not pid:
    print("ERROR: No Roblox process found")
    exit(1)

print(f"PID: {pid}")

rc, maps = sh(f"grep libroblox.so /proc/{pid}/maps 2>/dev/null | head -1")
if "libroblox.so" not in maps:
    print("ERROR: libroblox.so not loaded")
    exit(1)

print("libroblox.so loaded, starting gdb...")

os.makedirs("/tmp/cap746", exist_ok=True)

gdb_script = r'''
set pagination off
set confirm off

python
import gdb, os, time

RUN = "/tmp/cap746"
pid = gdb.selected_inferior().pid
print(f"Attached to {pid}")

BASE = None
for line in open(f"/proc/{pid}/maps"):
    if "libroblox.so" in line:
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "00000000":
            BASE = int(parts[0].split("-")[0], 16)
            break

if not BASE:
    print("ERROR: no BASE")
    gdb.execute("quit")

print(f"BASE = {hex(BASE)}")
open(f"{RUN}/base.txt", "w").write(hex(BASE))

def u8(a):
    return int.from_bytes(gdb.selected_inferior().read_memory(a, 1).tobytes(), "little")

def u64(a):
    return int.from_bytes(gdb.selected_inferior().read_memory(a, 8).tobytes(), "little")

def rd(a, n):
    try:
        return gdb.selected_inferior().read_memory(a, n).tobytes()
    except:
        return b""

LOG = open(f"{RUN}/log.txt", "w")
CNT = {"chal": 0, "a7": 0, "ans": 0}
T0 = time.monotonic()
DEADLINE = T0 + 90

class BlobBp(gdb.Breakpoint):
    def stop(self):
        try:
            rsi = int(gdb.parse_and_eval("$rsi"))
            flag = u8(rsi)
            if flag & 1:
                ptr, length = u64(rsi + 16), u64(rsi + 8)
            else:
                length, ptr = flag >> 1, rsi + 1
            if 0 < length < 100000 and 0x1000 < ptr:
                blob = rd(ptr, length)
                idx = CNT["chal"]
                CNT["chal"] += 1
                open(f"{RUN}/chal_{idx:04d}.bin", "wb").write(blob)
                print(f"[CHAL] #{idx} {length}B")
                LOG.write(f"CHAL {idx} {length}B\n")
                LOG.flush()
        except Exception as e:
            print(f"[CHAL ERR] {e}")
        if time.monotonic() > DEADLINE:
            gdb.execute("quit")
        return False

class A7Bp(gdb.Breakpoint):
    def stop(self):
        try:
            rdi = int(gdb.parse_and_eval("$rdi"))
            idx = CNT["a7"]
            CNT["a7"] += 1
            if 0x1000 < rdi:
                ctx = rd(rdi, 512)
                open(f"{RUN}/a7_{idx:04d}.bin", "wb").write(ctx)
                print(f"[A7] #{idx}")
                LOG.write(f"A7 {idx}\n")
                LOG.flush()
        except Exception as e:
            print(f"[A7 ERR] {e}")
        if time.monotonic() > DEADLINE:
            gdb.execute("quit")
        return False

class AnsBp(gdb.Breakpoint):
    def stop(self):
        try:
            rax = int(gdb.parse_and_eval("$rax"))
            idx = CNT["ans"]
            CNT["ans"] += 1
            print(f"[ANS] #{idx} rax={hex(rax)}")
            LOG.write(f"ANS {idx} {hex(rax)}\n")
            LOG.flush()
            if 0x1000 < rax:
                open(f"{RUN}/ans_{idx:04d}.bin", "wb").write(rd(rax, 64))
        except Exception as e:
            print(f"[ANS ERR] {e}")
        if time.monotonic() > DEADLINE:
            gdb.execute("quit")
        return False

print("Setting breakpoints...")
BlobBp(f"*{BASE + 0x427a7d4}")
A7Bp(f"*{BASE + 0x6152814}")
AnsBp(f"*{BASE + 0x429b2f9}")
print("Breakpoints set. Running for 90 seconds...")
print("Rejoin a game to trigger capture!")
LOG.write("started\n")
LOG.flush()
end

continue
'''

open("/tmp/cap.gdb", "w").write(gdb_script)

print("\nRunning gdb for 90 seconds...")
rc, out = sh("gdb -p " + pid + " -x /tmp/cap.gdb 2>&1", timeout=120)
print(out)

print("\n=== FILES ===")
rc, out = sh("ls -la /tmp/cap746/")
print(out)

print("\n=== LOG ===")
rc, out = sh("cat /tmp/cap746/log.txt 2>/dev/null || echo 'no log'")
print(out)

sh("zip -r /tmp/captures.zip /tmp/cap746/")
print("\nSaved to /tmp/captures.zip")
