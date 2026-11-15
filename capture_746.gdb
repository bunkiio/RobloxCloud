  # capture_746.gdb - Capture script for Roblox 2.746 client
  # Run with: gdb -p $(pgrep -f libroblox) -x capture_746.gdb

  set pagination off
  set confirm off

  python
  import gdb, os, time

  ROOT = os.environ.get("RBX_ROOT", os.getcwd())
  RUN = os.environ.get("SCAP_DIR", os.path.join(ROOT, "cap746"))
  os.makedirs(RUN, exist_ok=True)
  LOG = open(os.path.join(RUN, "index.txt"), "a", buffering=1)
  T0 = time.monotonic()

  def u8(a): return int.from_bytes(gdb.selected_inferior().read_memory(a, 1).tobytes(), "little")
  def u32(a): return int.from_bytes(gdb.selected_inferior().read_memory(a, 4).tobytes(), "little")
  def u64(a): return int.from_bytes(gdb.selected_inferior().read_memory(a, 8).tobytes(), "little")
  def rd(a, n):
      try:
          return gdb.selected_inferior().read_memory(a, n).tobytes()
      except Exception:
          return b""

  pid = gdb.selected_inferior().pid
  BASE = None
  for line in open(f"/proc/{pid}/maps"):
      if "libroblox.so" in line and line.split()[2] == "00000000":
          BASE = int(line.split("-")[0], 16)
          break

  if BASE is None:
      print("ERROR: Could not find libroblox.so base")
      gdb.execute("quit")

  LOG.write(f"# BASE={hex(BASE)} pid={pid}\n")
  LOG.flush()
  print(f"BASE={hex(BASE)}")

  CNT = {"chal": 0, "ans": 0, "a7": 0}
  DEADLINE = T0 + 300


  def maybe_quit():
      if time.monotonic() > DEADLINE:
          LOG.write("# deadline reached, detaching\n"); LOG.flush()
          try:
              gdb.execute("detach")
              gdb.execute("quit")
          except Exception:
              pass


  class BlobDecoderBp(gdb.Breakpoint):
      def stop(self):
          try:
              rsi = int(gdb.parse_and_eval("$rsi"))
              flag_byte = u8(rsi)
              if flag_byte & 1:
                  data_ptr = u64(rsi + 16)
                  length = u64(rsi + 8)
              else:
                  length = flag_byte >> 1
                  data_ptr = rsi + 1

              if 0 < length < 100000 and 0x1000 < data_ptr < 0x800000000000:
                  blob = rd(data_ptr, length)
                  idx = CNT["chal"]; CNT["chal"] += 1
                  fn = os.path.join(RUN, f"chal_{idx:04d}_s{length}.bin")
                  open(fn, "wb").write(blob)
                  hdr = blob[:20].hex() if len(blob) >= 20 else blob.hex()
                  LOG.write(f"{time.monotonic() - T0:9.3f} CHAL idx={idx} size={length} head={hdr}\n")
                  LOG.flush()
                  print(f"[CHAL] Captured #{idx}, {length} bytes")
          except Exception as e:
              LOG.write(f"CHALERR {e}\n"); LOG.flush()
          maybe_quit()
          return False


  class A7BuilderBp(gdb.Breakpoint):
      def stop(self):
          try:
              rdi = int(gdb.parse_and_eval("$rdi"))
              rsi = int(gdb.parse_and_eval("$rsi"))
              idx = CNT["a7"]; CNT["a7"] += 1
              LOG.write(f"{time.monotonic() - T0:9.3f} A7BUILD rdi={rdi:#x} rsi={rsi:#x}\n")
              LOG.flush()
              print(f"[A7] Builder called #{idx}")
              if 0x1000 < rdi < 0x800000000000:
                  ctx = rd(rdi, 256)
                  fn = os.path.join(RUN, f"a7_ctx_{idx:04d}.bin")
                  open(fn, "wb").write(ctx)
          except Exception as e:
              LOG.write(f"A7ERR {e}\n"); LOG.flush()
          maybe_quit()
          return False


  class AnswerBp(gdb.Breakpoint):
      def stop(self):
          try:
              rax = int(gdb.parse_and_eval("$rax"))
              rbp = int(gdb.parse_and_eval("$rbp"))
              idx = CNT["ans"]; CNT["ans"] += 1
              LOG.write(f"{time.monotonic() - T0:9.3f} ANSWER rax={rax:#x}\n")
              LOG.flush()
              print(f"[ANS] Answer #{idx}: rax={rax:#x}")
              if 0x1000 < rax < 0x800000000000:
                  data = rd(rax, 64)
                  fn = os.path.join(RUN, f"ans_{idx:04d}.bin")
                  open(fn, "wb").write(data)
          except Exception as e:
              LOG.write(f"ANSERR {e}\n"); LOG.flush()
          maybe_quit()
          return False


  BlobDecoderBp(f"*{BASE + 0x427a7d4}", internal=False)
  print(f"Blob decoder bp at {hex(BASE + 0x427a7d4)}")

  AnswerBp(f"*{BASE + 0x429b2f9}", internal=False)
  print(f"Answer bp at {hex(BASE + 0x429b2f9)}")

  A7BuilderBp(f"*{BASE + 0x6152814}", internal=False)
  print(f"A7 builder bp at {hex(BASE + 0x6152814)}")

  print("746 capture ready - continuing...")
  LOG.write("# bps set\n")
  LOG.flush()
  end

  continue
