#!/usr/bin/env python3
"""
Capture 0x90 + A7 from the 746 Roblox client via GDB, for the RobloxCloud
web endpoint (no shell on the VM). Every hit prints full diagnostics, and any
captured packet is printed as base64 so it can be copied out of the browser.

Send framer offset (746): 0x301E650  (ported from 739 0x631BD58 by
string-anchor scan, cross-checked by prologue + 'ctrl' + struct offsets).
"""
import base64
import glob
import os
import subprocess
import sys
import time

CAP_DIR = "/tmp/cap746"
SEND_OFFSET = 0x301E650
os.makedirs(CAP_DIR, exist_ok=True)


def sh(cmd, timeout=120):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def banner(t):
    print(f"\n=== {t} ===", flush=True)


def show_dir():
    banner("FILES IN /tmp/cap746")
    rc, out = sh(f"ls -la {CAP_DIR}")
    print(out, flush=True)


def show_log():
    for name in ("gdb.log", "index.txt"):
        p = f"{CAP_DIR}/{name}"
        if os.path.exists(p):
            banner(name.upper())
            txt = open(p, errors="replace").read()
            print(txt[-3000:] if len(txt) > 3000 else txt, flush=True)


def print_captures():
    """Print any captured 0x90/A7 as base64 for copy-out. Returns True if found."""
    files = sorted(glob.glob(f"{CAP_DIR}/*_op90_*.bin")) + \
            sorted(glob.glob(f"{CAP_DIR}/*_opa7_*.bin"))
    if not files:
        return False
    banner("CAPTURED PACKETS")
    for fp in files:
        data = open(fp, "rb").read()
        name = os.path.basename(fp)
        print(f"\n--- {name}  ({len(data)} bytes) ---", flush=True)
        print(f"head: {data[:48].hex()}", flush=True)
        valid = (data[:1].hex() in ("90", "a7"))
        print(f"opcode 0x{data[:1].hex()}  valid: {valid}", flush=True)
        print("BASE64 (copy everything between the lines):", flush=True)
        print("----8<----", flush=True)
        print(base64.b64encode(data).decode(), flush=True)
        print("---->8----", flush=True)
    print("\nTo install on your VPS, for each block run:", flush=True)
    print("  echo 'PASTED_BASE64' | base64 -d > /opt/sandbox/Boblox/py/captures/NAME", flush=True)
    print("  0x90 -> acct2_90.bin (or your account's template)", flush=True)
    print("  a7   -> fresh_a7.bin", flush=True)
    return True


def gdb_alive():
    rc, out = sh("pgrep -f 'gdb.*cap746'")
    return [p for p in out.split("\n") if p.strip()] if rc == 0 else []


def find_target():
    """Return (pid, base) for the process with libroblox.so loaded."""
    for pat in ("cordial-run", "cordial", "libroblox"):
        rc, out = sh(f"pgrep -f '{pat}'")
        if rc != 0:
            continue
        for pid in [p.strip() for p in out.split("\n") if p.strip()]:
            rc2, maps = sh(f"grep -m1 -i libroblox /proc/{pid}/maps 2>/dev/null")
            if rc2 == 0 and maps and "libroblox" in maps.lower():
                base = int(maps.split("-")[0], 16)
                return pid, base, maps.strip()
    return None, None, None


def write_gdb_script(base):
    addr = base + SEND_OFFSET
    script = f'''set pagination off
set confirm off
python
import gdb, os
CAP_DIR = "{CAP_DIR}"
LOG = open(os.path.join(CAP_DIR, "index.txt"), "a", buffering=1)
def u8(a): return int.from_bytes(gdb.selected_inferior().read_memory(a,1).tobytes(),"little")
def u64(a): return int.from_bytes(gdb.selected_inferior().read_memory(a,8).tobytes(),"little")
BASE={hex(base)}
ADDR=BASE+{hex(SEND_OFFSET)}
print("BASE="+hex(BASE)+" ADDR="+hex(ADDR))
LOG.write("start BASE="+hex(BASE)+" ADDR="+hex(ADDR)+"\\n")
C={{"n":0}}
class Bp(gdb.Breakpoint):
    def stop(self):
        try:
            rdx=int(gdb.parse_and_eval("$rdx")); rcx=int(gdb.parse_and_eval("$rcx")); r8=int(gdb.parse_and_eval("$r8"))
            app=rdx&0xFF; chan=rcx&0xFFFFFFFF
            if app!=4 or chan!=1: return False
            ns=r8; flag=u8(ns+64)
            if flag:
                dp=u64(ns+32); length=u64(ns+40)
            else:
                dp=u64(ns+8); length=u64(ns+16)-dp
            consumed=u64(ns+72); begin=dp+consumed
            size=length-consumed if length>=consumed else 0
            if not (0<size<66000): return False
            payload=gdb.selected_inferior().read_memory(begin,size).tobytes()
            op=payload[0] if payload else 0
            i=C["n"]; C["n"]+=1
            fn=os.path.join(CAP_DIR,"msg_%04d_op%02x_sz%d.bin"%(i,op,size))
            open(fn,"wb").write(payload)
            LOG.write("%04d op=0x%02x size=%d -> %s\\n"%(i,op,size,fn))
            print("CAPTURED op=0x%02x size=%d"%(op,size))
        except Exception as e:
            LOG.write("ERR "+str(e)+"\\n"); print("ERR "+str(e))
        return False
try:
    Bp("*"+hex(ADDR), internal=False)
    print("BREAKPOINT SET OK")
    LOG.write("bp set ok\\n")
except Exception as e:
    print("BREAKPOINT FAILED: "+str(e))
    LOG.write("bp fail "+str(e)+"\\n")
end
continue
'''
    with open(f"{CAP_DIR}/cap746.gdb", "w") as f:
        f.write(script)
    return f"{CAP_DIR}/cap746.gdb"


def main():
    print("=== ROBLOX 746 0x90/A7 CAPTURE (GDB) ===", flush=True)
    print(f"send offset: {hex(SEND_OFFSET)}", flush=True)

    # 1) Already captured? Show + base64 and stop.
    if print_captures():
        show_log()
        print("\n[DONE] packets captured above. Copy the base64, then "
              "'rm -rf /tmp/cap746' to reset.", flush=True)
        return

    # 2) Can GDB even attach here? Quick probe once.
    probe_done = os.path.exists(f"{CAP_DIR}/.probed")
    if not probe_done:
        pid, base, maps = find_target()
        if pid:
            rc, out = sh(f"gdb -p {pid} -batch -ex 'printf \"ATTACH_OK\\n\"' -ex detach 2>&1", timeout=40)
            open(f"{CAP_DIR}/attach_probe.txt", "w").write(out)
            open(f"{CAP_DIR}/.probed", "w").write("1")
            banner("GDB ATTACH PROBE")
            print(out[-1500:], flush=True)
            if "Operation not permitted" in out or "ptrace" in out.lower():
                print("\n[!!] ptrace is BLOCKED on this VM — GDB cannot attach.", flush=True)
                print("     The Colab container likely lacks CAP_SYS_PTRACE.", flush=True)
                print("     Check: cat /proc/sys/kernel/yama/ptrace_scope", flush=True)

    # 3) Find target.
    pid, base, maps = find_target()
    if not pid:
        banner("NO TARGET")
        print("No process with libroblox.so. Is Roblox started / in a game?", flush=True)
        show_dir()
        return
    banner("TARGET")
    print(f"pid={pid} base={hex(base)}", flush=True)
    print(f"map: {maps}", flush=True)
    print(f"breakpoint VA: {hex(base + SEND_OFFSET)}", flush=True)

    # 4) Start GDB if not already running.
    alive = gdb_alive()
    if alive:
        banner("GDB STATUS")
        print(f"gdb attached, pid(s): {alive}", flush=True)
        print("If this pid changes every refresh, gdb is dying — see GDB.LOG below.", flush=True)
    else:
        script = write_gdb_script(base)
        sh(f"rm -f {CAP_DIR}/gdb.log")
        os.system(f"nohup timeout 600 gdb -p {pid} -x {script} -batch "
                  f"> {CAP_DIR}/gdb.log 2>&1 &")
        time.sleep(4)
        banner("GDB STARTED")
        print("launched; first output:", flush=True)

    show_log()
    show_dir()
    print("\n[NEXT] stay in a game, then refresh this page.", flush=True)
    print("       when it fires you'll see CAPTURED lines + base64 above.", flush=True)


if __name__ == "__main__":
    main()
