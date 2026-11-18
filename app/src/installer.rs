//! Privileged helper installer (`vless-tray install-helper`, `PLAN.md` §4 & `dist/README.md` §3.A).
//!
//! Locates `install-helper.sh`, `vless-tray-helper`, and `io.vless-tray.helper.plist` across both
//! `.app` bundle layouts and Cargo workspace builds, constructs a strictly escaped POSIX shell
//! command + AppleScript `do shell script ... with administrator privileges` expression, and
//! invokes `/usr/bin/osascript` without an intermediate shell.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Maximum valid macOS console user UID accepted by `dist/install-helper.sh`
/// (rejects `(uid_t)-2 == 4294967294` `nobody` and `(uid_t)-1 == 4294967295`).
pub const MAX_VALID_MACOS_OWNER_UID: u32 = 4_294_967_293;

/// Optional CLI overrides when invoking `vless-tray install-helper`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InstallerOverrides {
    pub script_path: Option<PathBuf>,
    pub helper_path: Option<PathBuf>,
    pub plist_path: Option<PathBuf>,
    pub owner_uid: Option<u32>,
}

/// Validated, existing filesystem paths required to install `io.vless-tray.helper`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedInstallerAssets {
    pub install_script: PathBuf,
    pub helper_bin: PathBuf,
    pub plist_file: PathBuf,
}

/// Errors produced during helper asset resolution, escaping, or `osascript` execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallerError {
    UnsupportedPlatform,
    InvalidOwnerUid(u32),
    InvalidPathEncoding(PathBuf),
    InvalidPathCharacters(String),
    MissingInstallScript { searched: Vec<PathBuf> },
    MissingHelperBinary { searched: Vec<PathBuf> },
    MissingLaunchdPlist { searched: Vec<PathBuf> },
    EmptyAssetFile(PathBuf),
    UserCancelled,
    OsascriptFailed { code: Option<i32>, stderr: String },
    Io(String),
}

impl fmt::Display for InstallerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(
                f,
                "privileged helper installation via launchd/osascript is only supported on macOS"
            ),
            Self::InvalidOwnerUid(uid) => write!(
                f,
                "invalid owner UID {uid}: run as a normal non-root macOS desktop user (1..={MAX_VALID_MACOS_OWNER_UID})"
            ),
            Self::InvalidPathEncoding(path) => {
                write!(f, "asset path is not valid UTF-8: {}", path.display())
            }
            Self::InvalidPathCharacters(detail) => {
                write!(
                    f,
                    "asset path contains forbidden control characters: {detail}"
                )
            }
            Self::MissingInstallScript { searched } => write!(
                f,
                "could not locate install-helper.sh (searched: {})",
                format_path_list(searched)
            ),
            Self::MissingHelperBinary { searched } => write!(
                f,
                "could not locate vless-tray-helper binary; build workspace binaries first (searched: {})",
                format_path_list(searched)
            ),
            Self::MissingLaunchdPlist { searched } => write!(
                f,
                "could not locate io.vless-tray.helper.plist manifest (searched: {})",
                format_path_list(searched)
            ),
            Self::EmptyAssetFile(path) => {
                write!(f, "installer asset file is empty: {}", path.display())
            }
            Self::UserCancelled => write!(f, "administrator authentication was cancelled"),
            Self::OsascriptFailed { code, stderr } => match code {
                Some(c) if stderr.is_empty() => {
                    write!(f, "helper installer exited with status {c}")
                }
                Some(c) => write!(f, "helper installer failed (exit {c}): {stderr}"),
                None => write!(f, "helper installer terminated by signal: {stderr}"),
            },
            Self::Io(msg) => write!(f, "I/O error running helper installer: {msg}"),
        }
    }
}

impl std::error::Error for InstallerError {}

fn format_path_list(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "<none>".to_string();
    }
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Validates that `uid` is a non-root macOS console user UID (`1..=4_294_967_293`).
pub fn validate_owner_uid(uid: u32) -> Result<(), InstallerError> {
    if uid == 0 || uid > MAX_VALID_MACOS_OWNER_UID {
        return Err(InstallerError::InvalidOwnerUid(uid));
    }
    Ok(())
}

/// Determines the current desktop user's UID, preferring `$SUDO_UID` if `vless-tray` was invoked
/// under `sudo`, otherwise querying `libc::getuid()`.
pub fn detect_current_owner_uid() -> Result<u32, InstallerError> {
    if let Ok(sudo_uid_raw) = std::env::var("SUDO_UID") {
        let trimmed = sudo_uid_raw.trim();
        if !trimmed.is_empty()
            && let Ok(parsed) = trimmed.parse::<u32>()
            && parsed > 0
        {
            validate_owner_uid(parsed)?;
            return Ok(parsed);
        }
    }

    // SAFETY: `libc::getuid()` is thread-safe, takes no arguments, and always returns the calling
    // process's real user ID without side effects or memory safety preconditions.
    let uid = unsafe { libc::getuid() };
    validate_owner_uid(uid)?;
    Ok(uid)
}

/// Escapes an arbitrary argument as a single POSIX single-quoted token (`'...'`), replacing every
/// embedded `'` with `'\''`.
///
/// Rejects strings containing NUL (`\0`), CR (`\r`), or LF (`\n`) so multiline or truncated
/// strings can never reach `do shell script`.
pub fn posix_shell_quote(arg: &str) -> Result<String, InstallerError> {
    if arg.is_empty() {
        return Ok("''".to_string());
    }
    if arg.bytes().any(|b| matches!(b, b'\0' | b'\r' | b'\n')) {
        return Err(InstallerError::InvalidPathCharacters(
            "NUL, CR, and LF characters are not allowed in installer paths".to_string(),
        ));
    }

    let mut out = String::with_capacity(arg.len() + 8);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    Ok(out)
}

/// Escapes `\` and `"` inside a string so it can be embedded safely inside an AppleScript `"..."`
/// double-quoted string literal.
pub fn escape_applescript_string(input: &str) -> Result<String, InstallerError> {
    if input.bytes().any(|b| matches!(b, b'\0' | b'\r' | b'\n')) {
        return Err(InstallerError::InvalidPathCharacters(
            "NUL, CR, and LF characters are not allowed in AppleScript command strings".to_string(),
        ));
    }

    let mut out = String::with_capacity(input.len() + 16);
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            other => out.push(other),
        }
    }
    Ok(out)
}

/// Builds the POSIX shell command line executed as `root` by `osascript`:
/// `'<install-helper.sh>' --uid <uid> --helper '<vless-tray-helper>' --plist '<plist>'`
pub fn build_install_shell_command(
    assets: &ResolvedInstallerAssets,
    owner_uid: u32,
) -> Result<String, InstallerError> {
    validate_owner_uid(owner_uid)?;

    let script_str = path_to_utf8(&assets.install_script)?;
    let helper_str = path_to_utf8(&assets.helper_bin)?;
    let plist_str = path_to_utf8(&assets.plist_file)?;

    let quoted_script = posix_shell_quote(script_str)?;
    let quoted_helper = posix_shell_quote(helper_str)?;
    let quoted_plist = posix_shell_quote(plist_str)?;

    Ok(format!(
        "{quoted_script} --uid {owner_uid} --helper {quoted_helper} --plist {quoted_plist}"
    ))
}

/// Wraps a POSIX shell command in an AppleScript `do shell script "..." with administrator privileges`
/// expression suitable for passing directly as `-e <expr>` to `/usr/bin/osascript`.
pub fn build_osascript_expression(shell_command: &str) -> Result<String, InstallerError> {
    let escaped = escape_applescript_string(shell_command)?;
    Ok(format!(
        "do shell script \"{escaped}\" with administrator privileges"
    ))
}

fn path_to_utf8(path: &Path) -> Result<&str, InstallerError> {
    path.to_str()
        .ok_or_else(|| InstallerError::InvalidPathEncoding(path.to_path_buf()))
}

/// Resolves `install-helper.sh`, `vless-tray-helper`, and `io.vless-tray.helper.plist` using the
/// current executable path and working directory.
pub fn resolve_installer_assets(
    overrides: &InstallerOverrides,
) -> Result<ResolvedInstallerAssets, InstallerError> {
    let current_exe = std::env::current_exe().ok();
    let cwd = std::env::current_dir().ok();
    resolve_installer_assets_from(current_exe.as_deref(), cwd.as_deref(), overrides)
}

/// Pure, deterministic asset resolver supporting:
/// 1. Explicit CLI overrides (`--script`, `--helper`, `--plist`).
/// 2. `.app` bundle layout (`Contents/MacOS/vless-tray` -> `Contents/Resources/install-helper.sh`,
///    `Contents/Library/LaunchDaemons/vless-tray-helper`, `Contents/Resources/io.vless-tray.helper.dev.plist`).
/// 3. Cargo workspace layout (`dist/install-helper.sh`, sibling or `target/{release,debug}/vless-tray-helper`,
///    `dist/io.vless-tray.helper.plist`).
pub fn resolve_installer_assets_from(
    current_exe: Option<&Path>,
    cwd: Option<&Path>,
    overrides: &InstallerOverrides,
) -> Result<ResolvedInstallerAssets, InstallerError> {
    let exe_dir = current_exe.and_then(Path::parent);

    // Detect `.app` bundle `Contents/` directory if `current_exe` is `<App>.app/Contents/MacOS/<bin>`.
    let bundle_contents_dir: Option<&Path> = exe_dir.and_then(|macos_dir| {
        if macos_dir.file_name().and_then(|n| n.to_str()) == Some("MacOS") {
            let parent = macos_dir.parent()?;
            if parent.file_name().and_then(|n| n.to_str()) == Some("Contents") {
                return Some(parent);
            }
        }
        None
    });

    // Collect candidate workspace root directories by walking ancestors of `exe_dir` and `cwd`.
    let mut workspace_roots: Vec<PathBuf> = Vec::new();
    for start in [exe_dir, cwd].into_iter().flatten() {
        for ancestor in start.ancestors() {
            if ancestor.join("dist").is_dir() && !workspace_roots.iter().any(|p| p == ancestor) {
                workspace_roots.push(ancestor.to_path_buf());
            }
        }
    }

    // 1. Resolve `install-helper.sh`.
    let install_script = if let Some(explicit) = &overrides.script_path {
        verify_non_empty_file(explicit)?.to_path_buf()
    } else {
        let mut script_candidates = Vec::new();
        if let Some(contents) = bundle_contents_dir {
            push_unique(
                &mut script_candidates,
                contents.join("Resources").join("install-helper.sh"),
            );
        }
        for root in &workspace_roots {
            push_unique(
                &mut script_candidates,
                root.join("dist").join("install-helper.sh"),
            );
        }
        if let Some(dir) = cwd {
            push_unique(
                &mut script_candidates,
                dir.join("dist").join("install-helper.sh"),
            );
        }
        select_first_valid_file(&script_candidates).ok_or(InstallerError::MissingInstallScript {
            searched: script_candidates,
        })?
    };

    // 2. Resolve `vless-tray-helper` binary.
    let helper_bin = if let Some(explicit) = &overrides.helper_path {
        verify_non_empty_file(explicit)?.to_path_buf()
    } else {
        let mut helper_candidates = Vec::new();
        if let Some(contents) = bundle_contents_dir {
            push_unique(
                &mut helper_candidates,
                contents
                    .join("Library")
                    .join("LaunchDaemons")
                    .join("vless-tray-helper"),
            );
        }
        if let Some(dir) = exe_dir {
            push_unique(&mut helper_candidates, dir.join("vless-tray-helper"));
            if dir.file_name().and_then(|n| n.to_str()) == Some("deps")
                && let Some(parent) = dir.parent()
            {
                push_unique(&mut helper_candidates, parent.join("vless-tray-helper"));
            }
        }
        for root in &workspace_roots {
            push_unique(
                &mut helper_candidates,
                root.join("target")
                    .join("release")
                    .join("vless-tray-helper"),
            );
            push_unique(
                &mut helper_candidates,
                root.join("target").join("debug").join("vless-tray-helper"),
            );
            for triple in ["aarch64-apple-darwin", "x86_64-apple-darwin"] {
                for profile in ["release", "debug"] {
                    push_unique(
                        &mut helper_candidates,
                        root.join("target")
                            .join(triple)
                            .join(profile)
                            .join("vless-tray-helper"),
                    );
                }
            }
        }
        if let Some(script_dir) = install_script.parent()
            && let Some(parent) = script_dir.parent()
        {
            push_unique(
                &mut helper_candidates,
                parent
                    .join("Library")
                    .join("LaunchDaemons")
                    .join("vless-tray-helper"),
            );
            push_unique(
                &mut helper_candidates,
                parent
                    .join("target")
                    .join("release")
                    .join("vless-tray-helper"),
            );
            push_unique(
                &mut helper_candidates,
                parent
                    .join("target")
                    .join("debug")
                    .join("vless-tray-helper"),
            );
        }
        select_first_valid_file(&helper_candidates).ok_or(InstallerError::MissingHelperBinary {
            searched: helper_candidates,
        })?
    };

    // 3. Resolve development LaunchDaemon plist (`io.vless-tray.helper.dev.plist` in `.app`
    //    `Contents/Resources/`, or `io.vless-tray.helper.plist` in `dist/`).
    let plist_file = if let Some(explicit) = &overrides.plist_path {
        verify_non_empty_file(explicit)?.to_path_buf()
    } else {
        let mut plist_candidates = Vec::new();
        if let Some(contents) = bundle_contents_dir {
            push_unique(
                &mut plist_candidates,
                contents
                    .join("Resources")
                    .join("io.vless-tray.helper.dev.plist"),
            );
        }
        if let Some(script_dir) = install_script.parent() {
            push_unique(
                &mut plist_candidates,
                script_dir.join("io.vless-tray.helper.dev.plist"),
            );
            push_unique(
                &mut plist_candidates,
                script_dir.join("io.vless-tray.helper.plist"),
            );
        }
        for root in &workspace_roots {
            push_unique(
                &mut plist_candidates,
                root.join("dist").join("io.vless-tray.helper.plist"),
            );
        }
        select_first_valid_file(&plist_candidates).ok_or(InstallerError::MissingLaunchdPlist {
            searched: plist_candidates,
        })?
    };

    // Ensure all resolved files are non-empty and UTF-8 representable.
    verify_non_empty_file(&install_script)?;
    verify_non_empty_file(&helper_bin)?;
    verify_non_empty_file(&plist_file)?;
    let _ = path_to_utf8(&install_script)?;
    let _ = path_to_utf8(&helper_bin)?;
    let _ = path_to_utf8(&plist_file)?;

    Ok(ResolvedInstallerAssets {
        install_script,
        helper_bin,
        plist_file,
    })
}

fn push_unique(vec: &mut Vec<PathBuf>, candidate: PathBuf) {
    if !vec.iter().any(|existing| existing == &candidate) {
        vec.push(candidate);
    }
}

fn verify_non_empty_file(path: &Path) -> Result<&Path, InstallerError> {
    let meta = fs::metadata(path)
        .map_err(|err| InstallerError::Io(format!("cannot stat {}: {err}", path.display())))?;
    if !meta.is_file() {
        return Err(InstallerError::Io(format!(
            "not a regular file: {}",
            path.display()
        )));
    }
    if meta.len() == 0 {
        return Err(InstallerError::EmptyAssetFile(path.to_path_buf()));
    }
    Ok(path)
}

fn select_first_valid_file(candidates: &[PathBuf]) -> Option<PathBuf> {
    for candidate in candidates {
        if let Ok(meta) = fs::metadata(candidate)
            && meta.is_file()
            && meta.len() > 0
        {
            return Some(candidate.clone());
        }
    }
    None
}

/// Runs the privileged helper installer via `/usr/bin/osascript` (or prints the exact command when
/// `dry_run` is `true`).
pub fn run_install_helper(
    overrides: &InstallerOverrides,
    dry_run: bool,
) -> Result<String, InstallerError> {
    let owner_uid = match overrides.owner_uid {
        Some(uid) => {
            validate_owner_uid(uid)?;
            uid
        }
        None => detect_current_owner_uid()?,
    };

    let assets = resolve_installer_assets(overrides)?;
    let shell_cmd = build_install_shell_command(&assets, owner_uid)?;
    let applescript_expr = build_osascript_expression(&shell_cmd)?;

    if dry_run {
        return Ok(format!(
            "/usr/bin/osascript -e {}",
            posix_shell_quote(&applescript_expr)?
        ));
    }

    if !cfg!(target_os = "macos") {
        return Err(InstallerError::UnsupportedPlatform);
    }

    let output = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(&applescript_expr)
        .output()
        .map_err(|err| InstallerError::Io(err.to_string()))?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            Ok(format!(
                "Installed io.vless-tray.helper (authorized UID {owner_uid})"
            ))
        } else {
            Ok(stdout)
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.contains("User canceled") || stderr.contains("(-128)") {
            return Err(InstallerError::UserCancelled);
        }
        Err(InstallerError::OsascriptFailed {
            code: output.status.code(),
            stderr,
        })
    }
}

/// Convenience wrapper invoked by the macOS menu bar `Install Privileged Helper…` action.
pub fn run_install_helper_default() -> Result<String, InstallerError> {
    run_install_helper(&InstallerOverrides::default(), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Simulates AppleScript's double-quoted string literal unescaping (`\\` -> `\`, `\"` -> `"`).
    fn simulate_applescript_string_eval(osascript_expr: &str) -> String {
        let inner = osascript_expr
            .strip_prefix("do shell script \"")
            .and_then(|s| s.strip_suffix("\" with administrator privileges"))
            .expect("valid do shell script wrapper");

        let mut unescaped = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                let next = chars
                    .next()
                    .expect("dangling backslash in AppleScript string");
                unescaped.push(next);
            } else {
                unescaped.push(ch);
            }
        }
        unescaped
    }

    #[test]
    fn posix_and_applescript_escaping_preserve_spaces_quotes_and_metacharacters() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Tricky path containing spaces, apostrophes, double quotes, dollar expansion, and backticks
        let tricky_bundle = dir
            .path()
            .join("Applications")
            .join("O'Connor's \"VLESS\" $HOME `id` Tray.app")
            .join("Contents");
        let macos_dir = tricky_bundle.join("MacOS");
        let resources_dir = tricky_bundle.join("Resources");
        let daemons_dir = tricky_bundle.join("Library").join("LaunchDaemons");

        fs::create_dir_all(&macos_dir).unwrap();
        fs::create_dir_all(&resources_dir).unwrap();
        fs::create_dir_all(&daemons_dir).unwrap();

        // Make install-helper.sh a real POSIX shell script that prints each received argv line!
        let script_path = resources_dir.join("install-helper.sh");
        fs::write(
            &script_path,
            "#!/bin/sh\nfor arg in \"$0\" \"$@\"; do printf '%s\\n' \"$arg\"; done\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let helper_path = daemons_dir.join("vless-tray-helper");
        fs::write(&helper_path, b"mach-o-helper-placeholder").unwrap();

        let dev_plist_path = resources_dir.join("io.vless-tray.helper.dev.plist");
        fs::write(&dev_plist_path, b"<plist version=\"1.0\"></plist>").unwrap();

        let tray_exe = macos_dir.join("vless-tray");
        fs::write(&tray_exe, b"mach-o-tray-placeholder").unwrap();

        let assets =
            resolve_installer_assets_from(Some(&tray_exe), None, &InstallerOverrides::default())
                .expect("resolve .app bundle assets");

        assert_eq!(assets.install_script, script_path);
        assert_eq!(assets.helper_bin, helper_path);
        assert_eq!(assets.plist_file, dev_plist_path);

        let shell_cmd = build_install_shell_command(&assets, 501).expect("build shell command");
        let applescript = build_osascript_expression(&shell_cmd).expect("build applescript");

        // Evaluate the AppleScript literal exactly as osascript does, then execute via /bin/sh -c
        // to prove zero command injection (`$HOME` and `` `id` `` are NOT expanded) and exact argv!
        let evaluated_shell = simulate_applescript_string_eval(&applescript);
        assert_eq!(evaluated_shell, shell_cmd);

        let sh_out = Command::new("/bin/sh")
            .arg("-c")
            .arg(&evaluated_shell)
            .output()
            .expect("execute /bin/sh");
        assert!(
            sh_out.status.success(),
            "sh failed: {}",
            String::from_utf8_lossy(&sh_out.stderr)
        );

        let lines: Vec<String> = String::from_utf8(sh_out.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(
            lines,
            vec![
                script_path.to_str().unwrap().to_string(),
                "--uid".to_string(),
                "501".to_string(),
                "--helper".to_string(),
                helper_path.to_str().unwrap().to_string(),
                "--plist".to_string(),
                dev_plist_path.to_str().unwrap().to_string(),
            ]
        );
    }

    #[test]
    fn standard_applications_bundle_path_formats_cleanly() {
        let assets = ResolvedInstallerAssets {
            install_script: PathBuf::from(
                "/Applications/VLESS Tray.app/Contents/Resources/install-helper.sh",
            ),
            helper_bin: PathBuf::from(
                "/Applications/VLESS Tray.app/Contents/Library/LaunchDaemons/vless-tray-helper",
            ),
            plist_file: PathBuf::from(
                "/Applications/VLESS Tray.app/Contents/Resources/io.vless-tray.helper.dev.plist",
            ),
        };
        let shell_cmd = build_install_shell_command(&assets, 501).unwrap();
        assert_eq!(
            shell_cmd,
            "'/Applications/VLESS Tray.app/Contents/Resources/install-helper.sh' --uid 501 --helper '/Applications/VLESS Tray.app/Contents/Library/LaunchDaemons/vless-tray-helper' --plist '/Applications/VLESS Tray.app/Contents/Resources/io.vless-tray.helper.dev.plist'"
        );
        let osascript = build_osascript_expression(&shell_cmd).unwrap();
        assert_eq!(
            osascript,
            "do shell script \"'/Applications/VLESS Tray.app/Contents/Resources/install-helper.sh' --uid 501 --helper '/Applications/VLESS Tray.app/Contents/Library/LaunchDaemons/vless-tray-helper' --plist '/Applications/VLESS Tray.app/Contents/Resources/io.vless-tray.helper.dev.plist'\" with administrator privileges"
        );
    }

    #[test]
    fn resolves_cargo_workspace_layout_and_validates_uid_and_control_chars() {
        let ws = tempfile::tempdir().expect("workspace tempdir");
        let dist_dir = ws.path().join("dist");
        let release_dir = ws.path().join("target").join("release");
        fs::create_dir_all(&dist_dir).unwrap();
        fs::create_dir_all(&release_dir).unwrap();

        let script = dist_dir.join("install-helper.sh");
        let plist = dist_dir.join("io.vless-tray.helper.plist");
        let helper = release_dir.join("vless-tray-helper");
        let tray = release_dir.join("vless-tray");

        fs::write(&script, b"#!/bin/bash\n").unwrap();
        fs::write(&plist, b"<plist/>").unwrap();
        fs::write(&helper, b"helper-bin").unwrap();
        fs::write(&tray, b"tray-bin").unwrap();

        let resolved =
            resolve_installer_assets_from(Some(&tray), None, &InstallerOverrides::default())
                .expect("resolve workspace layout");
        assert_eq!(resolved.install_script, script);
        assert_eq!(resolved.helper_bin, helper);
        assert_eq!(resolved.plist_file, plist);

        // Also resolves when binary lives in an external CARGO_TARGET_DIR and cwd is workspace root
        let ext_target = tempfile::tempdir().expect("ext target");
        let ext_debug = ext_target.path().join("debug");
        fs::create_dir_all(&ext_debug).unwrap();
        let ext_tray = ext_debug.join("vless-tray");
        let ext_helper = ext_debug.join("vless-tray-helper");
        fs::write(&ext_tray, b"tray").unwrap();
        fs::write(&ext_helper, b"helper").unwrap();

        let ext_resolved = resolve_installer_assets_from(
            Some(&ext_tray),
            Some(ws.path()),
            &InstallerOverrides::default(),
        )
        .expect("resolve external CARGO_TARGET_DIR");
        assert_eq!(ext_resolved.install_script, script);
        assert_eq!(ext_resolved.helper_bin, ext_helper);
        assert_eq!(ext_resolved.plist_file, plist);

        // UID validation boundaries
        assert!(validate_owner_uid(0).is_err());
        assert!(validate_owner_uid(501).is_ok());
        assert!(validate_owner_uid(1000).is_ok());
        assert!(validate_owner_uid(MAX_VALID_MACOS_OWNER_UID).is_ok());
        assert!(validate_owner_uid(MAX_VALID_MACOS_OWNER_UID + 1).is_err());
        assert!(validate_owner_uid(u32::MAX).is_err());

        // Control character rejection
        assert!(posix_shell_quote("/tmp/bad\npath").is_err());
        assert!(posix_shell_quote("/tmp/bad\0path").is_err());
        assert!(escape_applescript_string("echo hi\rmalicious").is_err());
    }
}
