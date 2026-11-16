#!/usr/bin/env python3
"""
Capture 0x90 packet from 746 Roblox client using Frida.
Hooks memcpy/memmove to catch packet before QUIC encryption.
"""
import subprocess
import os
import time
import sys
import glob

def sh(cmd, timeout=120):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()

# if called with --bg, we're the background worker
if "--bg" in sys.argv:
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
    
    os.chmod("/tmp/cap746", 0o777)
    open("/tmp/cap746/status.txt", "w").write(f"attached pid={pid} base={hex(base)}\n")
    os.chmod("/tmp/cap746/status.txt", 0o666)
    
    # frida script - hook 0x90 builder function directly in libroblox
    # Function at 0x434ba9e builds the 0x90 packet
    # We hook function entry/exit to capture the output buffer
    frida_script = '''
var got90 = false;
var packetCount = 0;

// Find libroblox base
var libroblox = Process.getModuleByName("libroblox.so");
var base = libroblox.base;
console.log("[FRIDA] libroblox base: " + base);

// The 0x90 builder function - found via static analysis
// At 0x434ba9e, writes 0x90 byte at 0x434bc37
var FUNC_90_OFFSET = 0x434ba9e;
var func90Addr = base.add(FUNC_90_OFFSET);
console.log("[FRIDA] 0x90 builder at: " + func90Addr);

// Hook the function
Interceptor.attach(func90Addr, {
    onEnter: function(args) {
        console.log("[0x90 FUNC] Called!");
        // Save args - typically arg0 or arg1 is output buffer, arg2 might be context
        this.arg0 = args[0];
        this.arg1 = args[1];
        this.arg2 = args[2];
        console.log("[0x90 FUNC] arg0=" + args[0] + " arg1=" + args[1] + " arg2=" + args[2]);
    },
    onLeave: function(ret) {
        console.log("[0x90 FUNC] Returned: " + ret);
        
        // Check arg0 and arg1 for 0x90 packet data
        var ptrs = [this.arg0, this.arg1, ret];
        for (var i = 0; i < ptrs.length; i++) {
            var p = ptrs[i];
            if (p.isNull()) continue;
            try {
                var first4 = p.readByteArray(4);
                var arr = new Uint8Array(first4);
                console.log("[0x90 FUNC] ptr" + i + " first4: " + arr[0].toString(16) + " " + arr[1].toString(16) + " " + arr[2].toString(16) + " " + arr[3].toString(16));
                
                if (arr[0] == 0x90 && arr[1] == 0x01) {
                    console.log("[0x90 FUNC] FOUND PACKET at ptr" + i);
                    // Dump 12KB
                    var data = p.readByteArray(12000);
                    var fname = "/tmp/cap746/m90_func_" + (packetCount++) + ".bin";
                    var f = new File(fname, "wb");
                    f.write(data);
                    f.close();
                    console.log("[0x90] Saved to " + fname);
                    got90 = true;
                }
            } catch(e) {
                console.log("[0x90 FUNC] ptr" + i + " unreadable");
            }
        }
    }
});

// Also do a memory scan after connection is established
var libc = Process.getModuleByName("libc.so.6");

// Hook connect() to know when connection happens
var connectAddr = libc.getExportByName("connect");
Interceptor.attach(connectAddr, {
    onEnter: function(args) {
        console.log("[connect] called");
    },
    onLeave: function(ret) {
        if (!got90) {
            console.log("[connect] returned, scheduling memory scan...");
            setTimeout(function() {
                console.log("[scan] Scanning for 0x90 packet in memory...");
                Process.enumerateRanges('rw-').forEach(function(range) {
                    if (got90) return;
                    if (range.size < 10000 || range.size > 50000000) return;
                    
                    try {
                        Memory.scan(range.base, range.size, "90 01 ?? 00 00 00 03", {
                            onMatch: function(addr, size) {
                                if (got90) return;
                                try {
                                    var preview = addr.readByteArray(100);
                                    var arr = new Uint8Array(preview);
                                    var str = "";
                                    for (var i = 0; i < arr.length; i++) {
                                        if (arr[i] >= 32 && arr[i] < 127) str += String.fromCharCode(arr[i]);
                                    }
                                    if (str.indexOf("User") != -1) {
                                        console.log("[scan] FOUND at " + addr + ": " + str.substring(0, 50));
                                        var data = addr.readByteArray(12000);
                                        var fname = "/tmp/cap746/m90_scan_" + (packetCount++) + ".bin";
                                        var f = new File(fname, "wb");
                                        f.write(data);
                                        f.close();
                                        console.log("[0x90] Saved to " + fname);
                                        got90 = true;
                                    }
                                } catch(e) {}
                            },
                            onComplete: function() {}
                        });
                    } catch(e) {}
                });
            }, 2000);
        }
    }
});

setInterval(function() {
    var status = "m90=" + got90 + " count=" + packetCount;
    var f = new File("/tmp/cap746/status.txt", "w");
    f.write(status);
    f.close();
}, 2000);

console.log("[FRIDA] Hooked 0x90 builder function + memory scan");
console.log("[FRIDA] Join a game now!");
'''
    
    open("/tmp/frida_capture.js", "w").write(frida_script)
    cmd = f"timeout 120 frida -p {pid} -l /tmp/frida_capture.js > /tmp/cap746/frida.log 2>&1"
    os.system(cmd)
    sys.exit(0)

# --- main entry point ---

print("=== ROBLOX 746 0x90 CAPTURE ===", flush=True)
print("", flush=True)

# check for results
matches = glob.glob("/tmp/cap746/m90_*.bin") + glob.glob("/tmp/cap746/m90_embedded_*.bin")
if matches:
    print("=== CAPTURE RESULTS ===", flush=True)
    rc, out = sh("ls -la /tmp/cap746/")
    print(out, flush=True)
    print("", flush=True)
    
    for fpath in sorted(matches):
        sz = os.path.getsize(fpath)
        with open(fpath, "rb") as f:
            data = f.read()
        fname = os.path.basename(fpath)
        print(f"{fname}: {sz} bytes", flush=True)
        print(f"  First 64 bytes: {data[:64].hex()}", flush=True)
        if len(data) > 0 and data[0] == 0x90:
            print(f"  ✓ 0x90 opcode confirmed", flush=True)
    
    if os.path.exists("/tmp/cap746/frida.log"):
        print("", flush=True)
        print("=== FRIDA LOG (last 20 lines) ===", flush=True)
        log = open("/tmp/cap746/frida.log").read()
        lines = log.strip().split('\n')
        print('\n'.join(lines[-20:]), flush=True)
    
    sys.exit(0)

# check if running
if os.path.exists("/tmp/cap746/status.txt"):
    print("Capture running...", flush=True)
    print("Status:", open("/tmp/cap746/status.txt").read(), flush=True)
    
    if os.path.exists("/tmp/cap746/frida.log"):
        print("", flush=True)
        print("=== FRIDA LOG ===", flush=True)
        log = open("/tmp/cap746/frida.log").read()
        lines = log.strip().split('\n')
        print('\n'.join(lines[-15:]), flush=True)
    
    print("", flush=True)
    print("No 0x90 packet yet. Join a game!", flush=True)
    print("To restart: rm -rf /tmp/cap746 && run again", flush=True)
    sys.exit(0)

# start new capture
rc, out = sh("which frida")
if rc != 0:
    print("Installing frida-tools...", flush=True)
    sh("pip install frida-tools", timeout=120)

sh("rm -rf /tmp/cap746")
os.makedirs("/tmp/cap746", exist_ok=True)
os.chmod("/tmp/cap746", 0o777)

script_path = os.path.abspath(__file__)
cmd = f"nohup python3 {script_path} --bg > /tmp/cap746/bg.log 2>&1 &"
os.system(cmd)

time.sleep(1)

if os.path.exists("/tmp/cap746/status.txt"):
    status = open("/tmp/cap746/status.txt").read()
    print(f"Capture started!", flush=True)
    print(f"Status: {status}", flush=True)
else:
    print("Capture starting...", flush=True)

print("", flush=True)
print("NOW JOIN A GAME!", flush=True)
print("Run /capture again to check for 0x90 packet.", flush=True)
