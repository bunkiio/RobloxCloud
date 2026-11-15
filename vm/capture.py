  #!/usr/bin/env python3
  """
  Standalone capture script - run this manually after you're in a game.
  Usage: python /content/rc/capture.py
  """
  import subprocess
  import os
  import time

  def sh(cmd, timeout=60):
      r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
      return r.returncode, (r.stdout + r.stderr).strip()

  print("=== ROBLOX CAPTURE SCRIPT ===")
  print("Looking for Roblox process...")

  # find roblox
  rc, out = sh("pgrep -f libroblox")
  pid = out.strip().split('\n')[0] if out.strip() else None

  if not pid:
      print("ERROR: No Roblox process found. Are you in a game?")
      exit(1)

  print(f"Found PID: {pid}")

  # verify it has libroblox.so
  rc, maps = sh(f"grep libroblox.so /proc/{pid}/maps 2>/dev/null | head -1")
  if "libroblox.so" not in maps:
      print("ERROR: libroblox.so not loaded in this process")
      exit(1)

  print("libroblox.so is loaded, attaching gdb...")

  os.makedirs("/tmp/cap746", exist_ok=True)

  gdb_script = '''
  set pagination off
  set confirm off

  python
  import gdb, os, time

  RUN = "/tmp/cap746"
  pid = gdb.selected_inferior().pid
  print(f"Attached to PID {pid}")

  # find BASE
  BASE = None
  for line in open(f"/proc/{pid}/maps"):
      if "libroblox.so" in line:
          parts = line.split()
          if len(parts) >= 3 and parts[2] == "00000000":
              BASE = int(parts[0].split("-")[0], 16)
              break

  if not BASE:
      print("ERROR: Could not find libroblox.so base address")
      gdb.execute("quit")

  print(f"BASE = {hex(BASE)}")
  open(f"{RUN}/base.txt", "w").write(hex(BASE) + "\\n")

  # helper functions
  def u8(a):
      return int.from_bytes(gdb.selected_inferior().read_memory(a, 1).tobytes(), "little")

  def u64(a):
      return int.from_bytes(gdb.selected_inferior().read_memory(a, 8).tobytes(), "little")

  def rd(a, n):
      try:
          return gdb.selected_inferior().read_memory(a, n).tobytes()
      except:
          return b""

  LOG = open(f"{RUN}/log.txt", "w")
  CNT = {"chal": 0, "a7": 0, "ans": 0}
  T0 = time.monotonic()
  DEADLINE = T0 + 90  # run for 90 seconds

  class BlobDecoderBp(gdb.Breakpoint):
      def stop(self):
          try:
              rsi = int(gdb.parse_and_eval("$rsi"))
              flag = u8(rsi)
              if flag & 1:
                  ptr, length = u64(rsi + 16), u64(rsi + 8)
              else:
                  length, ptr = flag >> 1, rsi + 1

              if 0 < length < 100000 and 0x1000 < ptr:
                  blob = rd(ptr, length)
                  idx = CNT["chal"]
                  CNT["chal"] += 1
                  fn = f"{RUN}/chal_{idx:04d}.bin"
                  open(fn, "wb").write(blob)
                  msg = f"[CHAL] #{idx} size={length}"
                  print(msg)
                  LOG.write(msg + "\\n")
                  LOG.flush()
          except Exception as e:
              print(f"[CHAL ERR] {e}")

          if time.monotonic() > DEADLINE:
              print("Deadline reached, detaching...")
              gdb.execute("quit")
          return False

  class A7BuilderBp(gdb.Breakpoint):
      def stop(self):
          try:
              rdi = int(gdb.parse_and_eval("$rdi"))
              idx = CNT["a7"]
              CNT["a7"] += 1
              if 0x1000 < rdi:
                  ctx = rd(rdi, 512)
                  fn = f"{RUN}/a7_{idx:04d}.bin"
                  open(fn, "wb").write(ctx)
                  msg = f"[A7] #{idx} captured context"
                  print(msg)
                  LOG.write(msg + "\\n")
                  LOG.flush()
          except Exception as e:
              print(f"[A7 ERR] {e}")

          if time.monotonic() > DEADLINE:
              gdb.execute("quit")
          return False

  class AnswerBp(gdb.Breakpoint):
      def stop(self):
          try:
              rax = int(gdb.parse_and_eval("$rax"))
              idx = CNT["ans"]
              CNT["ans"] += 1
              msg = f"[ANS] #{idx} rax={hex(rax)}"
              print(msg)
              LOG.write(msg + "\\n")
              LOG.flush()

              if 0x1000 < rax:
                  data = rd(rax, 64)
                  fn = f"{RUN}/ans_{idx:04d}.bin"
                  open(fn, "wb").write(data)
          except Exception as e:
              print(f"[ANS ERR] {e}")

          if time.monotonic() > DEADLINE:
              gdb.execute("quit")
          return False

  # set breakpoints at 746 offsets
  print("Setting breakpoints...")
  BlobDecoderBp(f"*{BASE + 0x427a7d4}")
  print(f"  Blob decoder @ {hex(BASE + 0x427a7d4)}")

  A7BuilderBp(f"*{BASE + 0x6152814}")
  print(f"  A7 builder @ {hex(BASE + 0x6152814)}")

  AnswerBp(f"*{BASE + 0x429b2f9}")
  print(f"  Answer @ {hex(BASE + 0x429b2f9)}")

  print(f"\\nCapture running for 90 seconds...")
  print("Join/rejoin a game to trigger the breakpoints!")
  LOG.write("Capture started\\n")
  LOG.flush()
  end

  continue
  '''

  open("/tmp/cap.gdb", "w").write(gdb_script)

  print("\nRunning gdb (will capture for 90 seconds)...")
  print("Join or rejoin a game now to trigger challenge/A7!\n")

  rc, out = sh("gdb -p " + pid + " -x /tmp/cap.gdb 2>&1", timeout=120)
  print(out)

  print("\n=== CAPTURE RESULTS ===")
  rc, out = sh("ls -la /tmp/cap746/")
  print(out)

  print("\n=== LOG ===")
  rc, out = sh("cat /tmp/cap746/log.txt 2>/dev/null || echo 'no log'")
  print(out)

  print("\n=== ZIPPING ===")
  sh("zip -r /tmp/captures.zip /tmp/cap746/")
  print("Results saved to /tmp/captures.zip")
