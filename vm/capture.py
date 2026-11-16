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
    
    # frida script - find 0x90 packet by searching for FFlag string writes
    # The packet contains "UserPlayerScripts" - when that string is written to a buffer,
    # scan backwards to find the 90 01 header
    frida_script = '''
var got90 = false;
var packetCount = 0;
var searchStr = "UserPlayerScripts";  // unique string in 0x90 packet

var libc = Process.getModuleByName("libc.so.6");

// Hook memcpy - when FFlag strings are copied into packet buffer
var memcpyAddr = libc.getExportByName("memcpy");
Interceptor.attach(memcpyAddr, {
    onEnter: function(args) {
        if (got90) return;
        var dst = args[0];
        var src = args[1];
        var len = args[2].toInt32();
        
        // Check if we're copying the FFlag string
        if (len >= searchStr.length && len < 100) {
            try {
                var data = src.readUtf8String(len);
                if (data && data.indexOf("UserPlayer") != -1) {
                    console.log("[memcpy] Found FFlag string copy: " + data);
                    console.log("[memcpy] dst=" + dst + " len=" + len);
                    
                    // Scan backwards from dst to find 90 01 header
                    for (var offset = 0; offset < 500; offset++) {
                        try {
                            var checkPtr = dst.sub(offset);
                            var b0 = checkPtr.readU8();
                            var b1 = checkPtr.add(1).readU8();
                            if (b0 == 0x90 && b1 == 0x01) {
                                console.log("[FOUND] 90 01 header at offset -" + offset);
                                // Try to determine packet size - scan forward for end
                                var packetStart = checkPtr;
                                var estSize = offset + 12000;  // estimate ~10KB after our position
                                console.log("[FOUND] Dumping " + estSize + " bytes from " + packetStart);
                                var fullData = packetStart.readByteArray(estSize);
                                var fname = "/tmp/cap746/m90_" + (packetCount++) + ".bin";
                                var f = new File(fname, "wb");
                                f.write(fullData);
                                f.close();
                                console.log("[0x90] Saved to " + fname);
                                got90 = true;
                                break;
                            }
                        } catch(e) {}
                    }
                }
            } catch(e) {}
        }
        
        // Also check larger copies that might be the whole packet
        if (!got90 && len > 8000 && len < 15000) {
            try {
                var preview = src.readByteArray(Math.min(len, 200));
                var arr = new Uint8Array(preview);
                
                // Check for 90 01 header
                if (arr[0] == 0x90 && arr[1] == 0x01) {
                    var str = "";
                    for (var i = 0; i < arr.length; i++) {
                        if (arr[i] >= 32 && arr[i] < 127) str += String.fromCharCode(arr[i]);
                    }
                    if (str.indexOf("User") != -1) {
                        console.log("[memcpy] Found full 0x90 packet! len=" + len);
                        var fullData = src.readByteArray(len);
                        var fname = "/tmp/cap746/m90_" + (packetCount++) + ".bin";
                        var f = new File(fname, "wb");
                        f.write(fullData);
                        f.close();
                        got90 = true;
                    }
                }
            } catch(e) {}
        }
    }
});

// Hook strlen - called when measuring FFlag strings before write
var strlenAddr = libc.getExportByName("strlen");
var strlenHits = 0;
Interceptor.attach(strlenAddr, {
    onEnter: function(args) {
        if (got90) return;
        try {
            var s = args[0].readUtf8String(50);
            if (s && s.indexOf("UserPlayer") != -1) {
                strlenHits++;
                if (strlenHits <= 3) {
                    console.log("[strlen] FFlag string: " + s);
                }
            }
        } catch(e) {}
    }
});

// Periodic memory scan - look for 90 01 followed by FFlag content in heap
var scanCount = 0;
function doMemoryScan() {
    if (got90 || scanCount > 5) return;
    scanCount++;
    console.log("[scan] Scanning memory for 0x90 packet...");
    
    Process.enumerateRanges('rw-').forEach(function(range) {
        if (got90) return;
        if (range.size < 10000 || range.size > 100000000) return;
        
        try {
            Memory.scan(range.base, range.size, "90 01 ?? 00 00 00", {
                onMatch: function(addr, size) {
                    if (got90) return;
                    try {
                        // Check if followed by FFlag-like content
                        var preview = addr.readByteArray(200);
                        var arr = new Uint8Array(preview);
                        var str = "";
                        for (var i = 0; i < arr.length; i++) {
                            if (arr[i] >= 32 && arr[i] < 127) str += String.fromCharCode(arr[i]);
                        }
                        if (str.indexOf("User") != -1 && str.indexOf("Script") != -1) {
                            console.log("[scan] FOUND 0x90 packet at " + addr);
                            console.log("[scan] Preview: " + str.substring(0, 100));
                            // Dump 12KB
                            var fullData = addr.readByteArray(12000);
                            var fname = "/tmp/cap746/m90_scan_" + (packetCount++) + ".bin";
                            var f = new File(fname, "wb");
                            f.write(fullData);
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
}

// Run memory scan periodically
setTimeout(doMemoryScan, 3000);
setTimeout(doMemoryScan, 8000);
setTimeout(doMemoryScan, 15000);

setInterval(function() {
    var status = "m90=" + got90 + " count=" + packetCount + " strlenHits=" + strlenHits;
    var f = new File("/tmp/cap746/status.txt", "w");
    f.write(status);
    f.close();
}, 2000);

console.log("[FRIDA] 0x90 capture v2 - hunting FFlag strings");
console.log("[FRIDA] Will scan memory + hook memcpy/strlen");
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
