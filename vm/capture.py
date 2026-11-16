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
    
    # frida script - scan for 0x90 packet by signature
    frida_script = '''
var got90 = false;
var packetCount = 0;

var libc = Process.getModuleByName("libc.so.6");
var memcpyAddr = libc.getExportByName("memcpy");
var memmoveAddr = libc.getExportByName("memmove");

function checkFor90Packet(funcName, src, len) {
    // 0x90 packets are 8-15KB, start with 90 01, and contain FFlag strings
    if (len < 5000 || len > 20000) return;
    
    try {
        var first4 = src.readByteArray(4);
        var arr = new Uint8Array(first4);
        
        // Must start with 90 01 (not just 90)
        if (arr[0] == 0x90 && arr[1] == 0x01) {
            console.log("[" + funcName + "] Found 0x90 0x01 header! len=" + len);
            console.log("[" + funcName + "] First 64 bytes: " + hexdump(src, {length: 64, header: false}));
            
            var preview = src.readByteArray(Math.min(len, 500));
            var previewArr = new Uint8Array(preview);
            var str = "";
            for (var i = 0; i < previewArr.length; i++) {
                if (previewArr[i] >= 32 && previewArr[i] < 127) {
                    str += String.fromCharCode(previewArr[i]);
                }
            }
            
            console.log("[" + funcName + "] ASCII: " + str.substring(0, 150));
            
            // Look for FFlag indicators
            if (str.indexOf("User") != -1 || str.indexOf("Enable") != -1 || str.indexOf("Integration") != -1 || str.indexOf("Script") != -1) {
                console.log("[0x90 PACKET FOUND] len=" + len);
                
                var fullData = src.readByteArray(len);
                var fname = "/tmp/cap746/m90_" + (packetCount++) + ".bin";
                var f = new File(fname, "wb");
                f.write(fullData);
                f.close();
                console.log("[0x90] Saved to " + fname);
                got90 = true;
            }
        }
        
        // Also scan for embedded 90 01 pattern
        if (!got90) {
            var chunk = src.readByteArray(Math.min(len, 2000));
            var chunkArr = new Uint8Array(chunk);
            
            for (var i = 0; i < chunkArr.length - 20; i++) {
                // Look for 90 01 followed by reasonable bytes
                if (chunkArr[i] == 0x90 && chunkArr[i+1] == 0x01) {
                    var remaining = len - i;
                    if (remaining > 8000 && remaining < 15000) {
                        var sub = src.add(i).readByteArray(Math.min(remaining, 500));
                        var subArr = new Uint8Array(sub);
                        var subStr = "";
                        for (var j = 0; j < subArr.length; j++) {
                            if (subArr[j] >= 32 && subArr[j] < 127) {
                                subStr += String.fromCharCode(subArr[j]);
                            }
                        }
                        
                        if (subStr.indexOf("User") != -1 || subStr.indexOf("Script") != -1) {
                            console.log("[0x90 EMBEDDED] Found at offset " + i + " remaining=" + remaining);
                            console.log("[0x90 EMBEDDED] ASCII: " + subStr.substring(0, 100));
                            var fullData = src.add(i).readByteArray(remaining);
                            var fname = "/tmp/cap746/m90_embedded_" + (packetCount++) + ".bin";
                            var f = new File(fname, "wb");
                            f.write(fullData);
                            f.close();
                            console.log("[0x90] Saved embedded to " + fname);
                            got90 = true;
                            break;
                        }
                    }
                }
            }
        }
    } catch(e) {}
}

Interceptor.attach(memcpyAddr, {
    onEnter: function(args) {
        checkFor90Packet("memcpy", args[1], args[2].toInt32());
    }
});

Interceptor.attach(memmoveAddr, {
    onEnter: function(args) {
        checkFor90Packet("memmove", args[1], args[2].toInt32());
    }
});

var reallocAddr = libc.getExportByName("realloc");
Interceptor.attach(reallocAddr, {
    onEnter: function(args) {
        this.oldPtr = args[0];
        this.newSize = args[1].toInt32();
    },
    onLeave: function(ret) {
        if (this.newSize > 8000 && this.newSize < 15000 && !ret.isNull()) {
            try {
                var first2 = ret.readByteArray(2);
                var arr = new Uint8Array(first2);
                if (arr[0] == 0x90 && arr[1] == 0x01) {
                    console.log("[realloc] Found 0x90 01 header in " + this.newSize + " byte alloc");
                    checkFor90Packet("realloc", ret, this.newSize);
                }
            } catch(e) {}
        }
    }
});

setInterval(function() {
    var status = "m90=" + got90 + " count=" + packetCount;
    var f = new File("/tmp/cap746/status.txt", "w");
    f.write(status);
    f.close();
}, 2000);

console.log("[FRIDA] 0x90 packet capture hooks installed");
console.log("[FRIDA] Looking for packets starting with 0x90 0x01 and containing FFlag strings");
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
