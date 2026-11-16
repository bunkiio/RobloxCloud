#!/usr/bin/env python3
"""
Capture challenge blob from 746 Roblox client using Frida.
Runs in background so it doesn't block the streamer.

RUN THIS BEFORE JOINING A GAME.
"""
import subprocess
import os
import time
import sys

def sh(cmd, timeout=120):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()

# if called with --bg, we're the background worker
if "--bg" in sys.argv:
    # this is the actual capture logic
    os.makedirs("/tmp/cap746", exist_ok=True)
    
    # find cordial-run with libroblox
    rc, out = sh("pgrep -f cordial-run")
    pids = [p for p in out.strip().split('\n') if p.strip()]
    
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
        open("/tmp/cap746/error.txt", "w").write("no libroblox process found")
        sys.exit(1)
    
    open("/tmp/cap746/status.txt", "w").write(f"attached pid={pid} base={hex(base)}\n")
    
    # frida script - pass base address directly since module lookup fails
    frida_script = f'''
const BLOB_OFF = 0x427a7d4;
const A7_OFF = 0x6152814;
const BASE = ptr("{hex(base)}");

var base = BASE;
console.log("[FRIDA] Using base: " + base);

var gotChal = false;
var gotA7 = false;

// Hook challenge blob decoder
Interceptor.attach(base.add(BLOB_OFF), {
    onEnter: function(args) {
        if (gotChal) return;
        var strPtr = args[1];
        try {
            var flag = strPtr.readU8();
            var ptr, len;
            if (flag & 1) {
                len = strPtr.add(8).readU64().toNumber();
                ptr = strPtr.add(16).readPointer();
            } else {
                len = flag >> 1;
                ptr = strPtr.add(1);
            }
            if (len > 0 && len < 100000) {
                var blob = ptr.readByteArray(len);
                var f = new File("/tmp/cap746/challenge.bin", "wb");
                f.write(blob);
                f.close();
                console.log("[CHAL] " + len + " bytes");
                gotChal = true;
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
            if (rdi.toInt32() > 0x1000) {
                var ctx = rdi.readByteArray(2048);
                var f = new File("/tmp/cap746/a7_context.bin", "wb");
                f.write(ctx);
                f.close();
            }
            if (rsi.toInt32() > 0x1000) {
                var rsiData = rsi.readByteArray(512);
                var f2 = new File("/tmp/cap746/a7_rsi.bin", "wb");
                f2.write(rsiData);
                f2.close();
            }
            console.log("[A7] captured");
            gotA7 = true;
        } catch (e) {
            console.log("[A7 ERR] " + e);
        }
    }
});

setInterval(function() {
    var status = "chal=" + gotChal + " a7=" + gotA7;
    var f = new File("/tmp/cap746/status.txt", "w");
    f.write(status);
    f.close();
    if (gotChal && gotA7) {
        console.log("[DONE]");
    }
}, 2000);
'''
    
    open("/tmp/frida_capture.js", "w").write(frida_script)
    
    # run frida, log to file
    cmd = f"timeout 120 frida -p {pid} -l /tmp/frida_capture.js > /tmp/cap746/frida.log 2>&1"
    os.system(cmd)
    sys.exit(0)

# --- main entry point: spawn background worker and return immediately ---

print("=== ROBLOX 746 CAPTURE ===", flush=True)
print("", flush=True)

# check frida
rc, out = sh("which frida")
if rc != 0:
    print("Installing frida-tools...", flush=True)
    sh("pip install frida-tools", timeout=120)

# clean up old capture
sh("rm -rf /tmp/cap746")
os.makedirs("/tmp/cap746", exist_ok=True)

# spawn ourselves in background with --bg flag
script_path = os.path.abspath(__file__)
cmd = f"nohup python3 {script_path} --bg > /tmp/cap746/bg.log 2>&1 &"
os.system(cmd)

time.sleep(1)

# check if it started
if os.path.exists("/tmp/cap746/status.txt"):
    status = open("/tmp/cap746/status.txt").read()
    print(f"Capture started in background!", flush=True)
    print(f"Status: {status}", flush=True)
else:
    print("Capture starting...", flush=True)

print("", flush=True)
print("NOW JOIN A GAME! The capture is running in background.", flush=True)
print("", flush=True)
print("Check progress: cat /tmp/cap746/status.txt", flush=True)
print("View log: cat /tmp/cap746/frida.log", flush=True)
print("Results will be in /tmp/cap746/", flush=True)
