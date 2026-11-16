#!/usr/bin/env python3
"""
Capture challenge blob from 746 Roblox client using Frida.
Frida hooks don't pause the process - game runs normally.

RUN THIS BEFORE JOINING A GAME.
"""
import subprocess
import os
import time
import sys

def sh(cmd, timeout=120):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()

print("=== ROBLOX 746 CHALLENGE CAPTURE (Frida) ===", flush=True)
print("", flush=True)

# install frida if needed
print("Checking frida...", flush=True)
rc, out = sh("pip show frida-tools")
if rc != 0:
    print("Installing frida-tools...", flush=True)
    rc, out = sh("pip install frida-tools", timeout=120)
    if rc != 0:
        print(f"ERROR: failed to install frida: {out}", flush=True)
        sys.exit(1)

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

# 746 offsets
BLOB_OFF = 0x427a7d4
A7_OFF = 0x6152814

print(f"", flush=True)
print(f"Hooks:", flush=True)
print(f"  Challenge decoder: base + {hex(BLOB_OFF)}", flush=True)
print(f"  A7 builder:        base + {hex(A7_OFF)}", flush=True)
print(f"", flush=True)

# frida script
frida_script = '''
const BLOB_OFF = 0x427a7d4;
const A7_OFF = 0x6152814;

var libroblox = Process.getModuleByName("libroblox.so");
var base = libroblox.base;

console.log("[FRIDA] libroblox.so base: " + base);
console.log("[FRIDA] Hooks installed. JOIN A GAME NOW!");
console.log("[FRIDA] Game keeps running - no freeze.");

var gotChal = false;
var gotA7 = false;

// Hook challenge blob decoder
Interceptor.attach(base.add(BLOB_OFF), {
    onEnter: function(args) {
        if (gotChal) return;
        
        // rsi (args[1]) is std::string pointer
        var strPtr = args[1];
        
        try {
            // read std::string - check flag byte
            var flag = strPtr.readU8();
            var ptr, len;
            
            if (flag & 1) {
                // heap allocated: len at +8, ptr at +16
                len = strPtr.add(8).readU64().toNumber();
                ptr = strPtr.add(16).readPointer();
            } else {
                // SSO: len = flag >> 1, data at +1
                len = flag >> 1;
                ptr = strPtr.add(1);
            }
            
            if (len > 0 && len < 100000) {
                var blob = ptr.readByteArray(len);
                var f = new File("/tmp/cap746/challenge.bin", "wb");
                f.write(blob);
                f.close();
                
                console.log("[CHALLENGE CAPTURED] " + len + " bytes");
                console.log("  Preview: " + hexdump(ptr, {length: Math.min(48, len), header: false}));
                gotChal = true;
                
                if (gotA7) {
                    console.log("[DONE] Both captured!");
                }
            }
        } catch (e) {
            console.log("[CHAL ERR] " + e);
        }
    }
});

// Hook A7 builder
Interceptor.attach(base.add(A7_OFF), {
    onEnter: function(args) {
        if (gotA7) return;
        
        var rdi = args[0];
        var rsi = args[1];
        
        try {
            // dump context
            if (rdi.toInt32() > 0x1000) {
                var ctx = rdi.readByteArray(2048);
                var f = new File("/tmp/cap746/a7_context.bin", "wb");
                f.write(ctx);
                f.close();
            }
            
            // dump rsi data
            if (rsi.toInt32() > 0x1000) {
                var rsiData = rsi.readByteArray(512);
                var f2 = new File("/tmp/cap746/a7_rsi.bin", "wb");
                f2.write(rsiData);
                f2.close();
            }
            
            console.log("[A7 CAPTURED]");
            console.log("  rdi: " + rdi);
            console.log("  rsi: " + rsi);
            gotA7 = true;
            
            if (gotChal) {
                console.log("[DONE] Both captured!");
            }
        } catch (e) {
            console.log("[A7 ERR] " + e);
        }
    }
});

// Status check every 10s
setInterval(function() {
    console.log("[STATUS] chal=" + gotChal + " a7=" + gotA7);
}, 10000);
'''

open("/tmp/frida_capture.js", "w").write(frida_script)

print("Attaching frida (game will keep running)...", flush=True)
print("=" * 50, flush=True)

# run frida for 90 seconds
cmd = f"timeout 90 frida -p {pid} -l /tmp/frida_capture.js 2>&1"
proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

try:
    for line in proc.stdout:
        print(line.rstrip(), flush=True)
except KeyboardInterrupt:
    print("\n[INTERRUPTED]", flush=True)
    proc.kill()

proc.wait()
print("=" * 50, flush=True)

# show results
print("\n=== CAPTURED FILES ===", flush=True)
rc, out = sh("ls -la /tmp/cap746/")
print(out, flush=True)

for fname in ["challenge.bin", "a7_context.bin"]:
    fpath = f"/tmp/cap746/{fname}"
    if os.path.exists(fpath):
        sz = os.path.getsize(fpath)
        with open(fpath, "rb") as f:
            data = f.read(64)
        print(f"\n{fname}: {sz} bytes", flush=True)
        print(f"  hex: {data.hex()}", flush=True)
