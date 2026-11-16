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
    
    # make sure directory is writable by anyone (frida runs in target process context)
    os.chmod("/tmp/cap746", 0o777)
    
    open("/tmp/cap746/status.txt", "w").write(f"attached pid={pid} base={hex(base)}\n")
    os.chmod("/tmp/cap746/status.txt", 0o666)
    
    # frida script - capture 0x90 packet only
    frida_script = '''
const BASE = ptr("BASE_PLACEHOLDER");

var base = BASE;
console.log("[FRIDA] Using base: " + base);

var got90 = false;
var m90Count = 0;

// Find libc
var libc = Process.getModuleByName("libc.so.6");
console.log("[FRIDA] libc: " + libc.base);

var writeAddr = libc.getExportByName("write");
var sendtoAddr = libc.getExportByName("sendto");

console.log("[FRIDA] write @ " + writeAddr);
console.log("[FRIDA] sendto @ " + sendtoAddr);

// Hook write to find 0x90 packet
Interceptor.attach(writeAddr, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var buf = args[1];
        var len = args[2].toInt32();
        
        if (len > 100 && len < 50000 && fd > 2) {
            try {
                var data = buf.readByteArray(Math.min(len, 1024));
                var arr = new Uint8Array(data);
                
                // Look for 0x90 opcode followed by JSON with UserId
                for (var i = 0; i < Math.min(100, arr.length - 20); i++) {
                    if (arr[i] == 0x90) {
                        // Check if this looks like the 0x90 packet (has JSON nearby)
                        var snippet = "";
                        for (var j = i; j < Math.min(i + 200, arr.length); j++) {
                            if (arr[j] >= 32 && arr[j] < 127) {
                                snippet += String.fromCharCode(arr[j]);
                            }
                        }
                        if (snippet.indexOf("UserId") != -1 || snippet.indexOf("RandomSeed") != -1) {
                            console.log("[WRITE] Found 0x90 at offset " + i + ", fd=" + fd + ", len=" + len);
                            console.log("[WRITE] snippet: " + snippet.substring(0, 100));
                            
                            var fullData = buf.readByteArray(len);
                            var filename = "/tmp/cap746/write_90_" + (m90Count++) + ".bin";
                            var f = new File(filename, "wb");
                            f.write(fullData);
                            f.close();
                            
                            // Extract just the 0x90 portion
                            var m90Len = len - i;
                            var m90Data = buf.add(i).readByteArray(m90Len);
                            var f2 = new File("/tmp/cap746/m90_packet.bin", "wb");
                            f2.write(m90Data);
                            f2.close();
                            console.log("[0x90] Extracted " + m90Len + " bytes");
                            got90 = true;
                            break;
                        }
                    }
                }
            } catch(e) {}
        }
    }
});

// Also hook sendto
Interceptor.attach(sendtoAddr, {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var buf = args[1];
        var len = args[2].toInt32();
        
        if (len > 100 && len < 50000) {
            try {
                var data = buf.readByteArray(Math.min(len, 1024));
                var arr = new Uint8Array(data);
                
                for (var i = 0; i < Math.min(100, arr.length - 20); i++) {
                    if (arr[i] == 0x90) {
                        var snippet = "";
                        for (var j = i; j < Math.min(i + 200, arr.length); j++) {
                            if (arr[j] >= 32 && arr[j] < 127) {
                                snippet += String.fromCharCode(arr[j]);
                            }
                        }
                        if (snippet.indexOf("UserId") != -1 || snippet.indexOf("RandomSeed") != -1) {
                            console.log("[SENDTO] Found 0x90 at offset " + i + ", fd=" + fd + ", len=" + len);
                            var fullData = buf.readByteArray(len);
                            var f = new File("/tmp/cap746/sendto_90.bin", "wb");
                            f.write(fullData);
                            f.close();
                            got90 = true;
                            break;
                        }
                    }
                }
            } catch(e) {}
        }
    }
});

setInterval(function() {
    var status = "m90=" + got90;
    var f = new File("/tmp/cap746/status.txt", "w");
    f.write(status);
    f.close();
}, 2000);

console.log("[FRIDA] Hooks installed. Join a game to capture 0x90 packet.");
'''.replace("BASE_PLACEHOLDER", hex(base))
    
    open("/tmp/frida_capture.js", "w").write(frida_script)
    
    # run frida, log to file
    cmd = f"timeout 120 frida -p {pid} -l /tmp/frida_capture.js > /tmp/cap746/frida.log 2>&1"
    os.system(cmd)
    sys.exit(0)

# --- main entry point ---

print("=== ROBLOX 746 CAPTURE ===", flush=True)
print("", flush=True)

# check if capture already ran - show results
if os.path.exists("/tmp/cap746/m90_packet.bin") or os.path.exists("/tmp/cap746/sendto_90.bin") or os.path.exists("/tmp/cap746/write_90_0.bin"):
    print("=== CAPTURE RESULTS ===", flush=True)
    rc, out = sh("ls -la /tmp/cap746/")
    print(out, flush=True)
    print("", flush=True)
    
    if os.path.exists("/tmp/cap746/status.txt"):
        print("Status:", open("/tmp/cap746/status.txt").read(), flush=True)
    
    for fname in ["m90_packet.bin", "sendto_90.bin", "write_90_0.bin"]:
        fpath = f"/tmp/cap746/{fname}"
        if os.path.exists(fpath):
            sz = os.path.getsize(fpath)
            with open(fpath, "rb") as f:
                data = f.read()
            print(f"{fname}: {sz} bytes", flush=True)
            if fname == "m90_packet.bin":
                print(f"  FULL HEX:", flush=True)
                for i in range(0, min(len(data), 2048), 32):
                    row = data[i:i+32]
                    print(f"  {i:04x}: {row.hex()}", flush=True)
                if len(data) > 2048:
                    print(f"  ... ({len(data) - 2048} more bytes)", flush=True)
            else:
                print(f"  hex: {data[:128].hex()}", flush=True)
            if len(data) > 0 and data[0] == 0x90:
                print(f"  0x90 opcode confirmed", flush=True)
    
    if os.path.exists("/tmp/cap746/frida.log"):
        print("", flush=True)
        print("=== FRIDA LOG (last 30 lines) ===", flush=True)
        log = open("/tmp/cap746/frida.log").read()
        lines = log.strip().split('\n')
        print('\n'.join(lines[-30:]), flush=True)
    
    sys.exit(0)

# check if capture is running but no results yet
if os.path.exists("/tmp/cap746/status.txt"):
    print("Capture already running...", flush=True)
    print("", flush=True)
    print("Status:", open("/tmp/cap746/status.txt").read(), flush=True)
    
    if os.path.exists("/tmp/cap746/frida.log"):
        print("", flush=True)
        print("=== FRIDA LOG ===", flush=True)
        log = open("/tmp/cap746/frida.log").read()
        lines = log.strip().split('\n')
        print('\n'.join(lines[-20:]), flush=True)
    
    if os.path.exists("/tmp/cap746/bg.log"):
        print("", flush=True)
        print("=== BG LOG ===", flush=True)
        print(open("/tmp/cap746/bg.log").read()[-500:], flush=True)
    
    print("", flush=True)
    print("No captures yet. Are you in a game?", flush=True)
    print("To restart capture: rm -rf /tmp/cap746 then run again", flush=True)
    sys.exit(0)

# --- start new capture ---

# check frida
rc, out = sh("which frida")
if rc != 0:
    print("Installing frida-tools...", flush=True)
    sh("pip install frida-tools", timeout=120)

# clean up old capture
sh("rm -rf /tmp/cap746")
os.makedirs("/tmp/cap746", exist_ok=True)
os.chmod("/tmp/cap746", 0o777)  # world writable so frida can write

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
print("Run /capture again to check results.", flush=True)
