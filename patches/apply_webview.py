#!/usr/bin/env python3
  # Injects RobloxCloud's X11 webview support into a Cordial checkout by unique
  # string anchors (not a line-context diff), so it survives version drift.
  # Fails loudly if any anchor is missing. Idempotent.
  import sys, pathlib

  root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "cordial")

  # ---- looper.rs: TICK static + a tick() call after each apply_queued ----
  lp = root / "crates/cordial-runtime/src/android/looper.rs"
  s = lp.read_text()

  a = '*ON.get_or_init(|| std::env::var_os("CORDIAL_NO_CLOSE_EXIT").is_some())\n}'
  if a not in s:
      sys.exit("looper.rs: no_close_exit anchor missing")
  if "pub static TICK" not in s:
      s = s.replace(a, a + '\n\n'
          '/// Run once per pump tick, on the pump thread (X11 web views advance GLib here).\n'
          'pub static TICK: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();', 1)

  for anchor in ("crate::devctl::apply_queued(handle);", "crate::devctl::apply_queued(0);"):
      if anchor not in s:
          sys.exit(f"looper.rs: anchor missing: {anchor}")
      tick = anchor + "\n            if let Some(tick) = TICK.get() {\n                tick();\n            }"
      if tick not in s:
          s = s.replace(anchor, tick, 1)
  lp.write_text(s)

  # ---- load.rs: x11_web module, else-branch open(), guard arm() ----
  ld = root / "crates/cordial-runtime/src/bin/load.rs"
  s = ld.read_text()

  module = r'''#[cfg(feature = "webview")]
  mod x11_web {
      use gtk4::glib;
      use gtk4::prelude::*;

      pub fn arm() {
          match glib::MainContext::default().acquire() {
              Ok(guard) => std::mem::forget(guard),
              Err(e) => {
                  println!("  webview: could not take GLib's main context ({e}); web views stay unavailable");
                  return;
              }
          }
          let _ = cordial_runtime::android::looper::TICK.set(|| {
              let context = glib::MainContext::default();
              for _ in 0..64 {
                  if !context.iteration(false) {
                      break;
                  }
              }
          });
          println!("  webview: no Wayland host window; web views will open in their own X11 window");
      }

      fn gtk_up() -> bool {
          static UP: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
          *UP.get_or_init(|| {
              if let Err(e) = unsafe { glib::setenv("GDK_BACKEND", "x11", true) } {
                  println!("[webview] could not set GDK_BACKEND=x11: {e}");
              }
              gtk4::gdk::set_allowed_backends("x11");
              glib::set_prgname(Some("cordial-web"));
              match libadwaita::init() {
                  Ok(()) => true,
                  Err(e) => {
                      println!("[webview] GTK would not start on X11, so web views stay unavailable: {e}");
                      false
                  }
              }
          })
      }

      fn android_user_agent(ua: &str) -> String {
          const WINDOWS: &str = "ROBLOX Windows App ";
          let Some(at) = ua.find(WINDOWS) else {
              return ua.to_string();
          };
          let version = ua[at + WINDOWS.len()..].split(' ').next().unwrap_or_default();
          let device = ua[..at].replacen("; Cordial)", "; Cordial; 33)", 1);
          format!(
              "{device}ROBLOX Android App {version} Tablet Hybrid()  GooglePlayStore \
               RobloxApp/{version} (GlobalDist; GooglePlayStore)"
          )
      }

      pub fn open(request: cordial_runtime::webview::OpenWindowRequest) {
          if !gtk_up() {
              return;
          }
          let cookie =
              cordial_runtime::webview::roblox_session_cookie(&cordial_runtime::profile::active());
          let mut shell_request = cordial_runtime::webview::to_shell_request(&request, cookie);
          shell_request.user_agent = shell_request.user_agent.map(|ua| android_user_agent(&ua));
          let host = gtk4::Window::builder().title("Roblox").default_width(1280).default_height(720).build();
          host.present();
          match cordial_shell::webview::open(&host, &shell_request) {
              Some(dialog) => {
                  use libadwaita::prelude::AdwDialogExt;
                  println!("[webview] presented an openWindow request in its own X11 window");
                  let window = host.clone();
                  dialog.connect_closed(move |_| {
                      window.close();
                      cordial_runtime::webview::report_window_closed();
                  });
                  let window = host.clone();
                  dialog.connect_unmap(move |_| window.close());
              }
              None => {
                  host.close();
                  println!("[webview] openWindow request was refused by policy");
              }
          }
      }
  }

  '''

  fn = '#[cfg(feature = "webview")]\nfn install_webview_presenter() {'
  if fn not in s:
      sys.exit("load.rs: install_webview_presenter anchor missing")
  if "mod x11_web {" not in s:
      s = s.replace(fn, module + fn, 1)

  needle = "presenter ran with no Wayland host window open"
  if needle not in s:
      sys.exit("load.rs: else-branch anchor missing")
  if "x11_web::open(request);" not in s:
      i = s.index(needle)
      j = s.index("return;", i)
      s = s[:j] + "x11_web::open(request);\n                " + s[j:]

  guard = "if cordial_runtime::android::wayland::current().is_none() {"
  if guard not in s:
      sys.exit("load.rs: guard anchor missing")
  if "x11_web::arm();" not in s:
      s = s.replace(guard, guard + "\n        x11_web::arm();", 1)

  ld.write_text(s)
  print("apply_webview.py: injected OK")
