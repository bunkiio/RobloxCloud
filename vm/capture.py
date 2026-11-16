#!/usr/bin/env python3
"""
Hook the packet dispatcher to see all incoming opcodes.
If we see packets but no 0x9b challenge, it means challenge already happened.
"""
import subprocess
import os
import time

def sh(cmd, timeout=120):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()

print("=== ROBLOX CAPTURE (packet sniffer) ===", flush=True)

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
base_hex = out.split('-')[0]
BASE = int(base_hex, 16)
print(f"BASE = {hex(BASE)}", flush=True)

os.makedirs("/tmp/cap746", exist_ok=True)

# offsets we know:
# - blob decoder: 0x427a7d4 (only called when challenge arrives)
# - A7 builder: 0x6152814 (only called when sending A7 packet)
# - opcode dispatch: 0x1fb2d83 (called for EVERY incoming packet - we found this earlier)
#
# Let's hook the dispatch area to see what opcodes are coming in

# The dispatch at 0x1fb2d83 had: movzx eax, byte ptr [r14+rbx]
# That's reading the remapped opcode. Let's hook right there.
DISPATCH_OFF = 0x1fb2d83
BLOB_OFF = 0x427a7d4
A7_OFF = 0x6152814

DISPATCH_ADDR = BASE + DISPATCH_OFF
BLOB_ADDR = BASE + BLOB_OFF  
A7_ADDR = BASE + A7_OFF

print(f"Packet dispatch @ {hex(DISPATCH_ADDR)} (offset {hex(DISPATCH_OFF)})", flush=True)
print(f"Blob decoder @ {hex(BLOB_ADDR)} (offset {hex(BLOB_OFF)})", flush=True)
print(f"A7 builder @ {hex(A7_ADDR)} (offset {hex(A7_OFF)})", flush=True)

# gdb script: hook dispatch to log opcodes, hook blob decoder to capture challenge
capture_gdb = f'''set pagination off
set confirm off

python
import os
os.makedirs("/tmp/cap746", exist_ok=True)
opcode_counts = {{}}
got_challenge = False
challenge_data = None
end

# Hook the packet dispatch - this should fire constantly
break *{hex(DISPATCH_ADDR)}
commands 1
silent
python
import gdb
# at this point, eax should have the remapped opcode
try:
    eax = int(gdb.parse_and_eval("$eax")) & 0xFF
    if eax not in opcode_counts:
        opcode_counts[eax] = 0
        print(f"[NEW OPCODE] 0x{{eax:02x}}")
    opcode_counts[eax] += 1
except:
    pass
end
continue
end

# Hook blob decoder for challenge capture
break *{hex(BLOB_ADDR)}
commands 2
silent
python
import gdb
global got_challenge, challenge_data
if not got_challenge:
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
            open("/tmp/cap746/challenge.bin", "wb").write(blob)
            print(f"[CHALLENGE CAPTURED] {{ln}} bytes!")
            got_challenge = True
            challenge_data = blob[:64].hex()
    except Exception as e:
        print(f"[CHAL ERR] {{e}}")
end
continue
end

# Hook A7 builder
break *{hex(A7_ADDR)}
commands 3
silent
python
import gdb
rdi = int(gdb.parse_and_eval("$rdi"))
try:
    ctx = gdb.selected_inferior().read_memory(rdi, 512).tobytes()
    open("/tmp/cap746/a7_context.bin", "wb").write(ctx)
    print("[A7 CAPTURED]")
except Exception as e:
    print(f"[A7 ERR] {{e}}")
end
continue
end

# run for 25 seconds then report
python
import threading, time

def watchdog():
    time.sleep(25)
    print("\\n=== OPCODE SUMMARY ===")
    for op, cnt in sorted(opcode_counts.items()):
        print(f"  0x{{op:02x}}: {{cnt}} times")
    print(f"Total unique opcodes: {{len(opcode_counts)}}")
    print(f"Challenge captured: {{got_challenge}}")
    if challenge_data:
        print(f"Challenge preview: {{challenge_data}}")
    # save summary
    with open("/tmp/cap746/summary.txt", "w") as f:
        f.write(f"opcodes: {{dict(opcode_counts)}}\\n")
        f.write(f"challenge: {{got_challenge}}\\n")
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
print("GDB script written (packet sniffer)", flush=True)

print("Attaching - will monitor packets for 25 seconds...", flush=True)

cmd = f"timeout 35 gdb -batch -n -p {pid} -x /tmp/capture.gdb 2>&1"

rc, out = sh(cmd, timeout=40)
print(f"GDB exit code: {rc}", flush=True)

# filter output to just the interesting bits
lines = out.split('\n')
interesting = [l for l in lines if any(x in l for x in ['OPCODE', 'CHALLENGE', 'A7', 'SUMMARY', '0x', 'Total', 'captured', 'preview', 'ERR'])]
print("--- FILTERED OUTPUT ---", flush=True)
for line in interesting[-50:]:
    print(line, flush=True)
print("--- END ---", flush=True)

print("\n=== CAPTURED FILES ===", flush=True)
rc, out = sh("ls -la /tmp/cap746/")
print(out, flush=True)

# show summary if it exists
if os.path.exists("/tmp/cap746/summary.txt"):
    print("\n=== SUMMARY ===", flush=True)
    print(open("/tmp/cap746/summary.txt").read(), flush=True)
