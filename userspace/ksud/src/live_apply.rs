//! Live "Apply now" support.
//!
//! A module may only be activated against a running Android when its own
//! lifecycle code makes that safe. That is a property of the module's scripts,
//! not of the module tree, so it is audited per release and pinned here by
//! version code. Nothing is inferred from `service.sh` or from the absence of a
//! mount: an unaudited module never gets a live path.
//!
//! The table is deliberately small and hand-reviewed. The Manager only renders
//! the state it produces; eligibility is decided here and re-checked on apply.

/// How often a module may be applied without restarting Android.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Start-locked or idempotent: safe to apply again at any time.
    Live,
    /// Attached to one target process incarnation; once applied it must not be
    /// applied again until that process is replaced.
    Once,
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
impl Mode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Once => "once",
        }
    }
}

/// One audited module release.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub struct Audit {
    pub id: &'static str,
    /// The `versionCode` that was inspected. Any other installed version is
    /// offered off by default, because the code may have changed.
    pub version_code: u64,
    pub mode: Mode,
    /// Arguments for `busybox sh`, run in the module directory. The first item
    /// is a script path relative to the module, invoked by absolute path so the
    /// scripts' `MODDIR=${0%/*}` resolves correctly.
    pub apply: &'static [&'static str],
    /// The apply script is a long-lived foreground worker (start it detached
    /// and verify it is still alive instead of waiting for it).
    pub background: bool,
    /// For one-shot modules: the process the patch attaches to. Its identity
    /// decides whether an earlier apply is still live.
    pub target: Option<&'static str>,
    /// Optional read-only probe and the text that means "currently active".
    pub status: Option<(&'static [&'static str], &'static str)>,
    /// Short, user-facing reason shown next to the checkbox.
    pub summary: &'static str,
}

/// Audited releases: the only modules that may be applied without a restart.
///
/// Evidence per entry:
/// - `adb-port-publisher`: pidfile plus a "stop the previous watcher" step.
/// - `auto-spatialization`: settings lock and an idempotent write.
/// - `xbox-unknown-key`: `.watcher` directory and process identity check.
/// - `display-off`: `mkdir $RUN` singleton in `supervise.sh`.
/// - `wifi-adb`: `runtime/lock` and a boot-identity reset.
/// - `haptic-main`: `action.sh on` reaches the shared autostart worker lock.
/// - `mvhevc-eye-fix`: idempotent "already bound" check and a single watcher.
/// - `systemui-optimization`: `STATE/worker` lock; attaches to the live SystemUI.
/// - `window-curvature`: refuses a second attachment to the same SystemUI.
pub const AUDIT: &[Audit] = &[
    Audit {
        id: "gxr-display-off",
        version_code: 3,
        mode: Mode::Live,
        apply: &["service.sh"],
        background: false,
        target: None,
        status: None,
        summary: "Starts the supervised eye-loss watcher on the running system.",
    },
    Audit {
        id: "gxr_bsvr_adb_port_publisher",
        version_code: 3,
        mode: Mode::Live,
        // `service.sh` execs a foreground watcher.
        apply: &["service.sh"],
        background: true,
        target: None,
        status: None,
        summary: "Restarts the port watcher; it stops its previous instance first.",
    },
    Audit {
        id: "gxr_bsvr_auto_spatialization",
        version_code: 1,
        mode: Mode::Live,
        apply: &["service.sh"],
        background: false,
        target: None,
        status: None,
        summary: "Writes the Labs preference once; repeating it is harmless.",
    },
    Audit {
        id: "gxr_bsvr_xbox_unknown_key",
        version_code: 1,
        mode: Mode::Live,
        // `service.sh` runs the input scan loop in the foreground.
        apply: &["service.sh"],
        background: true,
        target: None,
        status: None,
        summary: "Starts the input watcher; a second start is ignored.",
    },
    Audit {
        id: "gxr_haptic_main",
        version_code: 13,
        mode: Mode::Live,
        apply: &["action.sh", "on"],
        background: false,
        target: None,
        status: None,
        summary: "Patches the running controller service; its worker re-applies after a restart.",
    },
    Audit {
        id: "gxr_mvhevc_eye_fix",
        version_code: 11,
        mode: Mode::Live,
        apply: &["action.sh", "on"],
        background: false,
        target: None,
        status: None,
        summary: "Binds the patched libraries; restart Gallery XR to load them.",
    },
    Audit {
        id: "gxr_systemui_optimization",
        version_code: 400,
        mode: Mode::Live,
        apply: &["service.sh"],
        background: false,
        target: None,
        status: None,
        summary: "Attaches to the running SystemUI; a second start is ignored.",
    },
    Audit {
        id: "gxr_wifi_adb",
        version_code: 10002,
        mode: Mode::Live,
        apply: &["service.sh"],
        background: false,
        target: None,
        status: None,
        summary: "Starts ADB over Wi-Fi on port 5555; repeating it is a no-op.",
    },
    Audit {
        id: "gxr_window_curvature",
        version_code: 103,
        mode: Mode::Once,
        // `control.sh run` is the long-lived supervisor `service.sh` backgrounds.
        apply: &["control.sh", "run"],
        background: true,
        target: Some("com.android.systemui"),
        status: Some((
            &["control.sh", "status"],
            "Runtime supervisor state is present",
        )),
        summary: "Attaches to the current SystemUI once; a restart is needed to attach again.",
    },
];

/// Find the audit entry for a module id.
pub fn lookup(id: &str) -> Option<&'static Audit> {
    AUDIT.iter().find(|entry| entry.id == id)
}

/// The checkbox default: on only for the exact release that was inspected.
pub const fn default_enabled(entry: &Audit, installed_version_code: u64) -> bool {
    entry.version_code == installed_version_code
}

#[cfg(target_os = "android")]
pub use runtime::{apply, apply_all, set_pref, state_for};

#[cfg(target_os = "android")]
mod runtime {
    use super::{Audit, Mode, default_enabled, lookup};
    use anyhow::{Context, Result, bail, ensure};
    use std::{
        fs::{self, File},
        io::Write,
        os::unix::fs::OpenOptionsExt,
        os::unix::process::CommandExt,
        path::{Path, PathBuf},
        process::{Command, ExitStatus, Stdio},
        time::{Duration, Instant},
    };

    use crate::{assets, defs, module, restart_stage};

    const PREF_DIR: &str = "/data/adb/ksu/live_apply";
    const STATE_DIR: &str = "/dev/ksu-live-apply";
    const LOCK_PATH: &str = "/dev/ksu-live-apply.lock";
    const APPLY_TIMEOUT: Duration = Duration::from_secs(120);
    const STATUS_TIMEOUT: Duration = Duration::from_secs(20);
    const TERM_GRACE: Duration = Duration::from_secs(10);
    const OUTPUT_LIMIT: usize = 64 * 1024;

    /// What the Manager renders for one module.
    pub struct LiveState {
        pub mode: Mode,
        pub default: bool,
        pub enabled: bool,
        pub applied: bool,
        pub reason: String,
    }

    fn pref_path(id: &str) -> PathBuf {
        Path::new(PREF_DIR).join(id)
    }

    fn marker_path(id: &str) -> PathBuf {
        Path::new(STATE_DIR).join(id)
    }

    fn log_file(name: &str) -> PathBuf {
        Path::new(STATE_DIR).join(format!("{name}.log"))
    }

    fn read_pref(id: &str) -> Option<bool> {
        let text = fs::read_to_string(pref_path(id)).ok()?;
        match text.trim() {
            "on" => Some(true),
            "off" => Some(false),
            _ => None,
        }
    }

    fn boot_id() -> String {
        fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .map_or_else(|_| String::new(), |value| value.trim().to_owned())
    }

    fn module_is_disabled(module_path: &Path) -> bool {
        module_path.join(defs::DISABLE_FILE_NAME).exists()
            || module_path.join(defs::REMOVE_FILE_NAME).exists()
    }

    fn tail(path: &Path) -> String {
        let mut bytes = fs::read(path).unwrap_or_default();
        if bytes.len() > OUTPUT_LIMIT {
            bytes.drain(..bytes.len() - OUTPUT_LIMIT);
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Start a module script by absolute path, with its output captured.
    fn spawn_script(
        module_path: &Path,
        id: &str,
        log_name: &str,
        argv: &[&str],
    ) -> Result<(std::process::Child, PathBuf)> {
        ensure!(!argv.is_empty(), "empty script path");
        fs::create_dir_all(STATE_DIR)?;
        let log_path = log_file(log_name);
        let log = File::create(&log_path)?;
        let script = module_path.join(argv[0]);
        let child = Command::new(assets::BUSYBOX_PATH)
            .arg("sh")
            .arg(&script)
            .args(&argv[1..])
            .current_dir(module_path)
            .envs(module::get_common_script_envs(Some(id)))
            .stdin(Stdio::null())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .process_group(0)
            .spawn()
            .with_context(|| format!("failed to run {}", argv.join(" ")))?;
        Ok((child, log_path))
    }

    /// Run a module script to completion, or terminate it politely.
    ///
    /// A patch in flight must never be SIGKILLed: a half-applied module leaves
    /// state behind that only a restart clears. On timeout the process group is
    /// asked to stop and then left alone if it does not.
    fn run_script(
        module_path: &Path,
        id: &str,
        log_name: &str,
        argv: &[&str],
        timeout: Duration,
    ) -> Result<(ExitStatus, String)> {
        let (mut child, log_path) = spawn_script(module_path, id, log_name, argv)?;

        let pid = child.id() as i32;
        let deadline = Instant::now() + timeout;
        let status = 'run: loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                // SAFETY: the child is alive and owns its process group.
                unsafe {
                    libc::kill(-pid, libc::SIGTERM);
                }
                let grace = Instant::now() + TERM_GRACE;
                loop {
                    if let Some(status) = child.try_wait()? {
                        break 'run status;
                    }
                    if Instant::now() >= grace {
                        bail!(
                            "apply did not finish within {}s; the module is left to restore itself",
                            timeout.as_secs()
                        );
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        };

        Ok((status, tail(&log_path)))
    }

    /// Start a long-lived worker and make sure it did not fail immediately.
    ///
    /// The child is left running: KernelSU exits after acknowledging, and the
    /// worker is reparented. Its own status probe, where one exists, is what
    /// confirms it actually attached.
    fn start_background(
        module_path: &Path,
        id: &str,
        log_name: &str,
        argv: &[&str],
    ) -> Result<String> {
        let (mut child, log_path) = spawn_script(module_path, id, log_name, argv)?;
        std::thread::sleep(Duration::from_millis(750));
        if let Some(status) = child.try_wait()? {
            let output = tail(&log_path);
            bail!("The module's worker exited immediately ({status}): {output}");
        }
        Ok(tail(&log_path))
    }

    fn lock() -> Result<File> {
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(LOCK_PATH)?;
        file.try_lock()
            .context("Another Apply now is running; retry when it finishes")?;
        Ok(file)
    }

    /// Run the module's own read-only probe, when it declares one.
    fn probe(entry: &Audit, module_path: &Path) -> bool {
        let Some((argv, needle)) = entry.status else {
            return false;
        };
        let id = entry.id;
        run_script(
            module_path,
            id,
            &format!("{id}.status"),
            argv,
            STATUS_TIMEOUT,
        )
        .is_ok_and(|(status, output)| status.success() && output.contains(needle))
    }

    /// Poll the probe while a backgrounded activation settles.
    fn wait_probe(entry: &Audit, module_path: &Path, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if probe(entry, module_path) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Identity `pid:starttime` of the named process, if it is running.
    fn target_identity(name: &str) -> Option<String> {
        for entry in fs::read_dir("/proc").ok()?.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
                continue;
            };
            let first = cmdline.split(|byte| *byte == 0).next().unwrap_or_default();
            if first != name.as_bytes() {
                continue;
            }
            let Ok(stat_line) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            let Some((_, after)) = stat_line.rsplit_once(')') else {
                continue;
            };
            let Some(start) = after.split_whitespace().nth(19) else {
                continue;
            };
            return Some(format!("{pid}:{start}"));
        }
        None
    }

    /// True when a one-shot module is still attached to the same target.
    ///
    /// The marker records the kernel boot and the target's `pid:starttime`, so
    /// a replaced app or system service invalidates it without asking the
    /// module, whose own state may outlive a killed supervisor.
    fn once_applied(entry: &Audit) -> bool {
        let Some(target) = entry.target else {
            return false;
        };
        let Ok(marker) = fs::read_to_string(marker_path(entry.id)) else {
            return false;
        };
        let mut lines = marker.lines();
        let boot = lines.next().unwrap_or_default();
        let identity = lines.next().unwrap_or_default();
        let current = target_identity(target);
        if boot == boot_id() && current.as_deref() == Some(identity) {
            return true;
        }
        let _ = fs::remove_file(marker_path(entry.id));
        false
    }

    /// Eligibility and preference for one module, or `None` when unaudited.
    pub fn state_for(
        id: &str,
        installed_version_code: u64,
        module_path: &Path,
    ) -> Option<LiveState> {
        let entry = lookup(id)?;
        let default = default_enabled(entry, installed_version_code);
        let enabled = read_pref(id).unwrap_or(default);
        let disabled = module_is_disabled(module_path);
        let applied = if disabled {
            let _ = fs::remove_file(marker_path(entry.id));
            false
        } else {
            // A one-shot module may already be attached from the boot service
            // stage, before Apply now ever wrote a marker.
            entry.mode == Mode::Once && (once_applied(entry) || probe(entry, module_path))
        };
        let reason = if default {
            entry.summary.to_owned()
        } else {
            format!(
                "Not audited for the installed version (v{installed_version_code}); Apply now is off by default."
            )
        };
        Some(LiveState {
            mode: entry.mode,
            default,
            enabled,
            applied,
            reason,
        })
    }

    /// Persist the per-module checkbox.
    pub fn set_pref(id: &str, value: &str) -> Result<()> {
        module::validate_module_id(id)?;
        lookup(id).context("This module does not support Apply now")?;
        let enabled = match value {
            "on" => true,
            "off" => false,
            _ => bail!("expected on or off"),
        };
        fs::create_dir_all(PREF_DIR)?;
        let path = pref_path(id);
        let tmp = path.with_extension("tmp");
        let mut file = File::create(&tmp)?;
        file.write_all(if enabled { b"on\n" } else { b"off\n" })?;
        file.sync_all()?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Why a module cannot be applied right now.
    fn skip_reason(entry: &Audit, module_path: &Path) -> Option<&'static str> {
        if module_is_disabled(module_path) {
            Some("Enable the module first, then apply it")
        } else if module_path.join(defs::UPDATE_FILE_NAME).exists() {
            Some("Finish the pending module update first")
        } else if entry.mode == Mode::Once && (once_applied(entry) || probe(entry, module_path)) {
            Some("This module is already applied; restart Android to apply it again")
        } else {
            None
        }
    }

    /// Apply one eligible module. The caller holds both locks.
    fn run(entry: &Audit, module_path: &Path, id: &str) -> Result<()> {
        // A one-shot patch is only meaningful against a live target; record its
        // identity so a later restart or app replacement invalidates the apply.
        let target_before = entry
            .target
            .map(|target| {
                target_identity(target)
                    .with_context(|| format!("The target process {target} is not running"))
            })
            .transpose()?;

        let began = Instant::now();
        let log_name = format!("{id}.apply");
        let output = if entry.background {
            start_background(module_path, id, &log_name, entry.apply)?
        } else {
            let (status, output) =
                run_script(module_path, id, &log_name, entry.apply, APPLY_TIMEOUT)?;
            ensure!(status.success(), "Apply failed (exit status {status})");
            output
        };
        if !output.is_empty() {
            print!("{output}");
        }
        ensure!(
            !module_is_disabled(module_path),
            "The module disabled itself while applying; inspect its log"
        );

        if entry.status.is_some() {
            ensure!(
                wait_probe(entry, module_path, STATUS_TIMEOUT),
                "Apply reported success but the module is not active"
            );
        }

        if let (Some(target), Some(identity)) = (entry.target, target_before) {
            ensure!(
                target_identity(target).as_deref() == Some(identity.as_str()),
                "The target process restarted while applying; nothing was recorded"
            );
            let boot = boot_id();
            fs::write(marker_path(id), format!("{boot}\n{identity}\n"))?;
        }

        println!(
            "GXR_LIVE_APPLY=OK id={id} mode={} elapsed_ms={}",
            entry.mode.as_str(),
            began.elapsed().as_millis()
        );
        Ok(())
    }

    /// Activate one module against the running system.
    pub fn apply(id: &str) -> Result<()> {
        module::validate_module_id(id)?;
        let entry = lookup(id).context("This module does not support Apply now")?;
        let installed = installed_version_code(id)?;
        let module_path = Path::new(defs::MODULE_DIR).join(id);
        ensure!(module_path.is_dir(), "Module {id} is not installed");

        // Serialize with installs and with the coordinated soft restart: a
        // restart must not begin while an apply is in flight.
        let _control = crate::gxr_update::control_lock()?;
        let _lock = lock()?;

        ensure!(!restart_stage::blocked(), "A soft restart is in progress");
        ensure!(
            read_pref(id).unwrap_or_else(|| default_enabled(entry, installed)),
            "Apply now is turned off for this module"
        );
        if let Some(reason) = skip_reason(entry, &module_path) {
            bail!("{reason}");
        }
        run(entry, &module_path, id)
    }

    /// Apply every checked module, continuing after individual failures.
    pub fn apply_all() -> Result<()> {
        let _control = crate::gxr_update::control_lock()?;
        let _lock = lock()?;
        ensure!(!restart_stage::blocked(), "A soft restart is in progress");

        let mut applied = 0_usize;
        let mut skipped = 0_usize;
        let mut failed = 0_usize;

        module::foreach_module(module::ModuleType::All, |module_path| {
            let Some(id) = module_path.file_name().and_then(|name| name.to_str()) else {
                return Ok(());
            };
            let Some(entry) = lookup(id) else {
                return Ok(());
            };
            let installed = module::read_module_prop(module_path)
                .ok()
                .and_then(|props| props.get("versionCode").cloned())
                .and_then(|value| value.trim().parse::<u64>().ok())
                .unwrap_or(0);
            if !read_pref(id).unwrap_or_else(|| default_enabled(entry, installed)) {
                skipped += 1;
                return Ok(());
            }
            if let Some(reason) = skip_reason(entry, module_path) {
                println!("GXR_LIVE_APPLY=SKIP id={id} reason=\"{reason}\"");
                skipped += 1;
                return Ok(());
            }
            match run(entry, module_path, id) {
                Ok(()) => applied += 1,
                Err(error) => {
                    failed += 1;
                    eprintln!("GXR_LIVE_APPLY=FAIL id={id} error={error:#}");
                }
            }
            Ok(())
        })?;

        println!("GXR_LIVE_APPLY=SUMMARY applied={applied} skipped={skipped} failed={failed}");
        if failed > 0 {
            bail!("{failed} module(s) failed to apply; see /dev/ksu-live-apply/");
        }
        Ok(())
    }

    fn installed_version_code(id: &str) -> Result<u64> {
        let props = module::read_module_prop(&Path::new(defs::MODULE_DIR).join(id))?;
        Ok(props
            .get("versionCode")
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(0))
    }
}

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use super::*;

    #[test]
    fn audit_ids_are_unique_and_well_formed() {
        let mut seen = std::collections::BTreeSet::new();
        for entry in AUDIT {
            assert!(seen.insert(entry.id), "duplicate audit id {}", entry.id);
            assert!(!entry.id.contains('/'));
            assert!(!entry.apply.is_empty(), "{} has no apply path", entry.id);
            assert!(
                entry.apply[0].ends_with(".sh"),
                "{} must run a script, so MODDIR resolves",
                entry.id
            );
            assert!(!entry.summary.is_empty());
        }
    }

    #[test]
    fn only_the_inspected_release_is_on_by_default() {
        let curvature = lookup("gxr_window_curvature").expect("curvature audited");
        assert_eq!(curvature.mode, Mode::Once);
        assert!(default_enabled(curvature, 103));
        assert!(
            !default_enabled(curvature, 104),
            "newer release is unverified"
        );
        assert!(
            !default_enabled(curvature, 102),
            "older release is unverified"
        );

        let haptics = lookup("gxr_haptic_main").expect("haptics audited");
        assert_eq!(haptics.mode, Mode::Live);
        assert!(default_enabled(haptics, 13));
        assert!(!default_enabled(haptics, 14));
    }

    #[test]
    fn unaudited_modules_have_no_live_path() {
        assert!(lookup("gxr-passthrough-anywhere").is_none());
        assert!(lookup("gxr-fanctl").is_none());
        assert!(lookup("gxr-usb-compat").is_none());
        assert!(lookup("gxr_framebuffer10").is_none());
    }

    #[test]
    fn one_shot_entries_declare_the_target_process() {
        for entry in AUDIT.iter().filter(|entry| entry.mode == Mode::Once) {
            assert!(
                entry.target.is_some(),
                "{} is one-shot without a target process",
                entry.id
            );
            assert!(
                entry.status.is_some(),
                "{} is one-shot without a status probe",
                entry.id
            );
        }
    }

    #[test]
    fn one_shot_entry_is_the_only_once_mode() {
        let once: Vec<_> = AUDIT
            .iter()
            .filter(|entry| entry.mode == Mode::Once)
            .map(|entry| entry.id)
            .collect();
        assert_eq!(once, vec!["gxr_window_curvature"]);
    }
}
