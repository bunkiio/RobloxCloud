#!/usr/bin/env python3
"""
Capture challenge blob from 746 Roblox client.

RUN THIS BEFORE JOINING A GAME. The challenge is sent when connecting to a
game server, not when Roblox is sitting on the home screen.

Flow:
1. Run this script right after @@READY (Roblox on home screen)
2. Script attaches gdb and sets breakpoints
3. Join a game through the web UI
4. Challenge arrives, script captures it
5. Script detaches after capture or 90s timeout
"""
import subprocess
import os
import time
import sys

def sh(cmd, timeout=120):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()

print("=== ROBLOX 746 CHALLENGE CAPTURE ===", flush=True)
print("", flush=True)
print("This script attaches BEFORE you join a game.", flush=True)
print("Once attached, JOIN A GAME through the Roblox UI.", flush=True)
print("The challenge will be captured when the connection happens.", flush=True)
print("", flush=True)

# find cordial-run with libroblox
rc, out = sh("pgrep -f cordial-run")
pids = [p for p in out.strip().split('\n') if p.strip()]
print(f"Found cordial-run PIDs: {pids}", flush=True)

if not pids:
    print("ERROR: cordial-run not running. Is Roblox open?", flush=True)
    sys.exit(1)

pid = None
base = None
for p in pids:
    rc, maps = sh(f"grep 'libroblox.so' /proc/{p}/maps 2>/dev/null | head -1")
    if rc == 0 and maps:
        pid = p
        base_hex = maps.split('-')[0]
        base = int(base_hex, 16)
        break

if not pid:
    print("ERROR: no process has libroblox.so loaded", flush=True)
    sys.exit(1)

print(f"Target PID: {pid}", flush=True)
print(f"libroblox.so base: {hex(base)}", flush=True)

os.makedirs("/tmp/cap746", exist_ok=True)

# 746 offsets (verified correct - shows proper function prologues)
BLOB_OFF = 0x427a7d4   # challenge blob decoder
A7_OFF = 0x6152814     # A7 packet builder

BLOB_ADDR = base + BLOB_OFF
A7_ADDR = base + A7_OFF

print(f"", flush=True)
print(f"Breakpoints:", flush=True)
print(f"  Challenge decoder: {hex(BLOB_ADDR)}", flush=True)
print(f"  A7 builder:        {hex(A7_ADDR)}", flush=True)
print(f"", flush=True)

# gdb script - captures challenge and A7, runs until both captured or 90s timeout
# NOTE: non-stop mode is set via -ex flags before attach
gdb_script = f'''set pagination off
set confirm off
set print thread-events off

python
import os, time
os.makedirs("/tmp/cap746", exist_ok=True)
start_time = time.time()
got_chal = False
got_a7 = False
chal_preview = ""
end

printf "\\n[GDB] Breakpoints set, game running. NOW JOIN A GAME!\\n"
printf "[GDB] Waiting up to 90 seconds for challenge...\\n\\n"

# breakpoint 1: challenge blob decoder
# rsi = pointer to std::string containing the challenge blob
break *{hex(BLOB_ADDR)}
commands 1
silent
python
import gdb, time
global got_chal, chal_preview
if not got_chal:
    elapsed = time.time() - start_time
    rsi = int(gdb.parse_and_eval("$rsi"))
    try:
        # std::string layout: flag byte at [0], if flag&1 then heap (ptr at +16, len at +8), else SSO (len = flag>>1, data at +1)
        flag = int.from_bytes(gdb.selected_inferior().read_memory(rsi, 1).tobytes(), "little")
        if flag & 1:
            ptr = int.from_bytes(gdb.selected_inferior().read_memory(rsi+16, 8).tobytes(), "little")
            ln = int.from_bytes(gdb.selected_inferior().read_memory(rsi+8, 8).tobytes(), "little")
        else:
            ln = flag >> 1
            ptr = rsi + 1
        if 0 < ln < 100000:
            blob = gdb.selected_inferior().read_memory(ptr, ln).tobytes()
            open("/tmp/cap746/challenge.bin", "wb").write(blob)
            chal_preview = blob[:48].hex()
            print(f"\\n[CHALLENGE CAPTURED] +{{elapsed:.1f}}s, {{ln}} bytes")
            print(f"  Preview: {{chal_preview}}...")
            got_chal = True
            # check if we have both
            if got_a7:
                print("\\n[DONE] Both challenge and A7 captured!")
                gdb.execute("detach")
    except Exception as e:
        print(f"[CHAL ERR] {{e}}")
end
continue -a &
end

# breakpoint 2: A7 packet builder  
# rdi = context pointer, rsi = some other param
break *{hex(A7_ADDR)}
commands 2
silent
python
import gdb, time, json
global got_a7
if not got_a7:
    elapsed = time.time() - start_time
    try:
        # dump registers
        regs = {{}}
        for r in ['rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15','rsp','rbp']:
            regs[r] = hex(int(gdb.parse_and_eval(f"${{r}}")))
        
        rdi = int(gdb.parse_and_eval("$rdi"))
        rsi = int(gdb.parse_and_eval("$rsi"))
        
        # dump context buffer
        if 0x1000 < rdi < 0x800000000000:
            ctx = gdb.selected_inferior().read_memory(rdi, 2048).tobytes()
            open("/tmp/cap746/a7_context.bin", "wb").write(ctx)
        
        # dump what rsi points to (might be the hash data)
        if 0x1000 < rsi < 0x800000000000:
            rsi_data = gdb.selected_inferior().read_memory(rsi, 512).tobytes()
            open("/tmp/cap746/a7_rsi.bin", "wb").write(rsi_data)
        
        # dump stack
        rsp = int(gdb.parse_and_eval("$rsp"))
        stack = gdb.selected_inferior().read_memory(rsp, 1024).tobytes()
        open("/tmp/cap746/a7_stack.bin", "wb").write(stack)
        
        # save registers
        open("/tmp/cap746/a7_regs.json", "w").write(json.dumps(regs, indent=2))
        
        print(f"\\n[A7 CAPTURED] +{{elapsed:.1f}}s")
        print(f"  rdi (context): {{regs['rdi']}}")
        print(f"  rsi (param):   {{regs['rsi']}}")
        got_a7 = True
        
        if got_chal:
            print("\\n[DONE] Both challenge and A7 captured!")
            gdb.execute("detach")
    except Exception as e:
        print(f"[A7 ERR] {{e}}")
end
continue -a &
end

# watchdog thread
python
import threading

def watchdog():
    import time
    time.sleep(90)
    print("\\n[TIMEOUT] 90 seconds elapsed")
    print(f"  Challenge captured: {{got_chal}}")
    print(f"  A7 captured: {{got_a7}}")
    # write summary
    with open("/tmp/cap746/summary.txt", "w") as f:
        f.write(f"timeout=true\\n")
        f.write(f"challenge={{got_chal}}\\n")
        f.write(f"a7={{got_a7}}\\n")
        if chal_preview:
            f.write(f"chal_preview={{chal_preview}}\\n")
    try:
        gdb.execute("detach", to_string=True)
    except:
        pass

t = threading.Thread(target=watchdog, daemon=True)
t.start()
end

# resume all threads and run in background (non-stop mode)
continue -a &
'''

open("/tmp/capture.gdb", "w").write(gdb_script)

# write a separate init file that runs FIRST to set non-stop mode
init_script = '''set non-stop on
set pagination off
set confirm off
'''
open("/tmp/gdb_init", "w").write(init_script)

print("Attaching gdb...", flush=True)
print("=" * 50, flush=True)

# use -ix to run init BEFORE anything, including attach
cmd = f"timeout 100 gdb -batch -n -ix /tmp/gdb_init -p {pid} -x /tmp/capture.gdb 2>&1"
proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

try:
    for line in proc.stdout:
        line = line.rstrip()
        # filter out thread spam
        if line.startswith("[New ") or line.startswith("[Thread ") or line.startswith("[Switching"):
            continue
        if line.startswith("warning:") or line.startswith("Using host"):
            continue
        if line:
            print(line, flush=True)
except KeyboardInterrupt:
    print("\n[INTERRUPTED]", flush=True)
    proc.kill()

proc.wait()
print("=" * 50, flush=True)

# show results
print("\n=== CAPTURED FILES ===", flush=True)
rc, out = sh("ls -la /tmp/cap746/")
print(out, flush=True)

# show previews
for fname in ["challenge.bin", "a7_context.bin"]:
    fpath = f"/tmp/cap746/{fname}"
    if os.path.exists(fpath):
        sz = os.path.getsize(fpath)
        with open(fpath, "rb") as f:
            data = f.read(64)
        print(f"\n{fname}: {sz} bytes", flush=True)
        print(f"  hex: {data.hex()}", flush=True)

if os.path.exists("/tmp/cap746/a7_regs.json"):
    print("\na7_regs.json:", flush=True)
    print(open("/tmp/cap746/a7_regs.json").read(), flush=True)
