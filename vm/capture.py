#!/usr/bin/env python3
"""
Capture 0x90 packet from 746 Roblox client.
Uses Frida to hook the packet serialization before QUIC encryption.

Strategy: The 0x90 packet contains a large JSON blob (~10KB) with FFlags.
We hook functions that handle large buffers and scan for 90 01 header + JSON.
"""
import subprocess
import os
import sys
import time
import glob

def sh(cmd, timeout=120):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()

print("=== ROBLOX 746 0x90 CAPTURE ===", flush=True)
print("", flush=True)

CAP_DIR = "/tmp/cap746"
os.makedirs(CAP_DIR, exist_ok=True)

# Check for results - any file with 90 header and FFlags
results = glob.glob(f"{CAP_DIR}/m90_*.bin")
if results:
    print("=== CAPTURE RESULTS ===", flush=True)
    for fpath in sorted(results):
        with open(fpath, "rb") as f:
            data = f.read()
        fname = os.path.basename(fpath)
        print(f"{fname}: {len(data)} bytes", flush=True)
        print(f"  First 64: {data[:64].hex()}", flush=True)
        if len(data) > 2 and data[0] == 0x90 and data[1] == 0x01:
            print(f"  ✓ Valid 0x90 0x01 header", flush=True)
    sys.exit(0)

# Check status
if os.path.exists(f"{CAP_DIR}/status.txt"):
    status = open(f"{CAP_DIR}/status.txt").read()
    print(f"Status: {status}", flush=True)
    
    if os.path.exists(f"{CAP_DIR}/frida.log"):
        log = open(f"{CAP_DIR}/frida.log").read()
        lines = log.strip().split('\n')
        print("", flush=True)
        print("=== FRIDA LOG (last 30) ===", flush=True)
        print('\n'.join(lines[-30:]), flush=True)
    
    if "m90=false" in status:
        print("", flush=True)
        print("No 0x90 yet. Join a game!", flush=True)
        print("To restart: rm -rf /tmp/cap746", flush=True)
    sys.exit(0)

# --- Start new capture ---

print("Starting capture...", flush=True)

# Clean
sh("rm -rf /tmp/cap746")
os.makedirs(CAP_DIR, exist_ok=True)
os.chmod(CAP_DIR, 0o777)

# Find process
rc, out = sh("pgrep -f cordial-run")
if rc != 0:
    print("ERROR: No cordial-run process", flush=True)
    sys.exit(1)

pids = [p.strip() for p in out.split('\n') if p.strip()]
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
    print("ERROR: No libroblox.so process", flush=True)
    sys.exit(1)

print(f"Target: pid={pid} base={hex(base)}", flush=True)

# Frida script - comprehensive packet capture
# Hook at multiple levels to catch 0x90 before encryption
frida_script = '''
var got90 = false;
var counter = 0;

// Find libroblox module - might be loaded with full path
var base = null;
Process.enumerateModules().forEach(function(m) {
    if (m.name.indexOf("libroblox") != -1 || m.path.indexOf("libroblox") != -1) {
        base = m.base;
        console.log("[*] Found: " + m.name + " at " + m.base);
    }
});
if (!base) {
    console.log("[*] libroblox not found, listing modules:");
    Process.enumerateModules().slice(0, 20).forEach(function(m) {
        console.log("    " + m.name + " @ " + m.base);
    });
}

// The 0x90 packet is built and then passed to the QUIC layer.
// We need to intercept it at the serialization point.

// Key insight from Boblox: the send function at offset 0x631BD58 receives:
//   rdx = app (4 for game channel)
//   rcx = chan (1 for reliable)  
//   r8 = pointer to packet struct
// The struct has the packet data at different offsets based on a flag.

// For 746, we need to find the equivalent function.
// Let's try hooking based on the pattern of app=4, chan=1 calls.

// Strategy 1: Hook write() and look for packet patterns in data being written
// to any fd (the QUIC socket or internal pipes)

var libc = Process.getModuleByName("libc.so.6");

// Look for sendmsg - QUIC uses this for UDP
var sendmsgAddr = libc.getExportByName("sendmsg");
if (sendmsgAddr) {
    Interceptor.attach(sendmsgAddr, {
        onEnter: function(args) {
            if (got90) return;
            var fd = args[0].toInt32();
            var msg = args[1];
            try {
                // msghdr->msg_iov
                var iov = msg.add(Process.pointerSize * 2).readPointer();
                var iovlen = msg.add(Process.pointerSize * 3).readUInt();
                
                for (var i = 0; i < Math.min(iovlen, 4); i++) {
                    var iov_base = iov.add(i * Process.pointerSize * 2).readPointer();
                    var iov_len = iov.add(i * Process.pointerSize * 2 + Process.pointerSize).readUInt();
                    
                    if (iov_len > 8000 && iov_len < 20000) {
                        var first8 = iov_base.readByteArray(8);
                        var arr = new Uint8Array(first8);
                        // Check for 0x90 0x01 header
                        if (arr[0] == 0x90 && arr[1] == 0x01) {
                            console.log("[sendmsg] FOUND 0x90 packet! len=" + iov_len);
                            var data = iov_base.readByteArray(iov_len);
                            var f = new File("/tmp/cap746/m90_sendmsg.bin", "wb");
                            f.write(data);
                            f.close();
                            got90 = true;
                        }
                    }
                }
            } catch(e) {}
        }
    });
    console.log("[*] Hooked sendmsg");
}

// Strategy 2: Scan for pattern in allocated memory periodically
// The 0x90 packet is built into a buffer that starts with 90 01 and has JSON

function scanForPacket() {
    if (got90) return;
    console.log("[scan] Scanning heap for 0x90 packet...");
    
    var found = 0;
    Process.enumerateRanges('rw-').forEach(function(range) {
        if (got90 || found > 3) return;
        if (range.size < 10000 || range.size > 100000000) return;
        
        try {
            // Search for: 90 01 followed by typical length byte and FFlag prefix
            // Pattern: 90 01 XX 00 00 00 (where XX is likely 20-30)
            Memory.scan(range.base, range.size, "90 01 ?? 00 00 00 03", {
                onMatch: function(addr, size) {
                    if (got90 || found > 3) return;
                    try {
                        // Read ahead and check for FFlag strings
                        var preview = addr.readByteArray(500);
                        var arr = new Uint8Array(preview);
                        var str = "";
                        for (var i = 0; i < arr.length; i++) {
                            if (arr[i] >= 32 && arr[i] < 127) str += String.fromCharCode(arr[i]);
                        }
                        
                        if (str.indexOf("User") != -1 && str.indexOf("Script") != -1) {
                            console.log("[scan] FOUND 0x90 at " + addr);
                            console.log("[scan] Preview: " + str.substring(0, 80));
                            found++;
                            
                            // Find packet end - scan for trailer pattern
                            // The packet ends with 5x u32 (20 bytes trailer)
                            var pktSize = 11000; // estimate
                            for (var sz = 9000; sz < 13000; sz += 100) {
                                try {
                                    var test = addr.add(sz).readByteArray(4);
                                    // Just dump 12KB and we'll trim later
                                } catch(e) { pktSize = sz - 100; break; }
                            }
                            
                            var data = addr.readByteArray(12000);
                            var fname = "/tmp/cap746/m90_scan_" + counter + ".bin";
                            counter++;
                            var f = new File(fname, "wb");
                            f.write(data);
                            f.close();
                            console.log("[scan] Saved " + fname);
                            got90 = true;
                        }
                    } catch(e) {}
                },
                onComplete: function() {}
            });
        } catch(e) {}
    });
}

// Run scans periodically
setTimeout(scanForPacket, 2000);
setTimeout(scanForPacket, 5000);
setTimeout(scanForPacket, 10000);
setTimeout(scanForPacket, 20000);
setTimeout(scanForPacket, 40000);

// Strategy 3: Hook large buffer allocations and watch for 90 01 header
var mallocAddr = libc.getExportByName("malloc");
var recentAllocs = [];

Interceptor.attach(mallocAddr, {
    onEnter: function(args) {
        this.size = args[0].toInt32();
    },
    onLeave: function(ret) {
        if (got90) return;
        // Track allocations in the 0x90 packet size range
        if (this.size > 9000 && this.size < 15000) {
            recentAllocs.push({ptr: ret, size: this.size, time: Date.now()});
            if (recentAllocs.length > 20) recentAllocs.shift();
        }
    }
});

// Check recent allocations for 0x90 content
setInterval(function() {
    if (got90) return;
    recentAllocs.forEach(function(alloc) {
        try {
            var first4 = alloc.ptr.readByteArray(4);
            var arr = new Uint8Array(first4);
            if (arr[0] == 0x90 && arr[1] == 0x01) {
                console.log("[malloc] Found 0x90 in recent alloc size=" + alloc.size);
                var preview = alloc.ptr.readByteArray(200);
                var parr = new Uint8Array(preview);
                var str = "";
                for (var i = 0; i < parr.length; i++) {
                    if (parr[i] >= 32 && parr[i] < 127) str += String.fromCharCode(parr[i]);
                }
                if (str.indexOf("User") != -1) {
                    console.log("[malloc] Confirmed FFlag content!");
                    var data = alloc.ptr.readByteArray(alloc.size);
                    var f = new File("/tmp/cap746/m90_malloc.bin", "wb");
                    f.write(data);
                    f.close();
                    got90 = true;
                }
            }
        } catch(e) {}
    });
}, 1000);

// Status file
setInterval(function() {
    var status = "m90=" + got90 + " scans=" + counter;
    var f = new File("/tmp/cap746/status.txt", "w");
    f.write(status);
    f.close();
}, 2000);

console.log("[*] 0x90 capture ready - join a game!");
'''

# Write and run frida
script_path = f"{CAP_DIR}/capture.js"
with open(script_path, "w") as f:
    f.write(frida_script)

print("Attaching frida...", flush=True)

# Make sure frida is installed
rc, _ = sh("which frida")
if rc != 0:
    print("Installing frida-tools...", flush=True)
    sh("pip install frida-tools", timeout=180)

cmd = f"nohup timeout 180 frida -p {pid} -l {script_path} > {CAP_DIR}/frida.log 2>&1 &"
os.system(cmd)

time.sleep(2)

if os.path.exists(f"{CAP_DIR}/frida.log"):
    log = open(f"{CAP_DIR}/frida.log").read()
    if "libroblox.so base" in log:
        print("Frida attached!", flush=True)
    print(log[:500], flush=True)

open(f"{CAP_DIR}/status.txt", "w").write(f"started pid={pid}")

print("", flush=True)
print("NOW JOIN A GAME!", flush=True)
print("Run /capture again to check for 0x90.", flush=True)
