#!/usr/bin/env python3
import subprocess
import os
import time

def sh(cmd, timeout=60):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()

print("=== ROBLOX CAPTURE DEBUG ===")

# show all processes
print("\n--- All processes ---")
rc, out = sh("ps aux | head -50")
print(out)

print("\n--- Processes with 'roblox' in name (case insensitive) ---")
rc, out = sh("ps aux | grep -i roblox")
print(out)

print("\n--- Processes with 'cordial' in name ---")
rc, out = sh("ps aux | grep -i cordial")
print(out)

print("\n--- All pgrep results ---")
rc, out = sh("pgrep -a '.' 2>/dev/null | head -30")
print(out)

print("\n--- Looking for any .so files in any process maps ---")
rc, out = sh("for p in $(ls /proc | grep -E '^[0-9]+$' | head -20); do echo \"=== PID $p ===\"; cat /proc/$p/maps 2>/dev/null | grep -E '\\.so' | head -5; done")
print(out[:3000])

print("\n--- Specifically looking for libroblox ---")
rc, out = sh("for p in $(ls /proc | grep -E '^[0-9]+$'); do grep -l libroblox /proc/$p/maps 2>/dev/null && echo \"Found in PID $p\"; done")
print(out if out else "Not found in any process")

print("\n--- Cordial builds directory ---")
rc, out = sh("ls -la /home/player/.local/share/cordial/builds/ 2>/dev/null || echo 'no builds dir'")
print(out)

rc, out = sh("find /home/player -name 'libroblox.so' 2>/dev/null | head -5")
print(f"libroblox.so locations: {out}")

print("\n=== END DEBUG ===")
