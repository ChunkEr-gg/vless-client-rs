//! macOS menu-bar process (`PLAN.md` §5.5 & §7).
//!
//! Runs a `winit` event loop with `ActivationPolicy::Accessory` (no Dock icon),
//! `with_default_menu(false)`, `with_activate_ignoring_other_apps(false)`, and strict
//! `ControlFlow::Wait` idle discipline (`0%` CPU when nothing happens). Spawns `vless-engine ipc`
//! via [`RuntimeSupervisor`] and spawns `vless-tray --settings` on demand as an isolated
//! short-lived process so the menu-bar agent never initializes a GPU/renderer context.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use block2::RcBlock;
use muda::{CheckMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu};
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2_app_kit::{
    NSApplicationActivationOptions, NSRunningApplication, NSWorkspace,
    NSWorkspaceDidWakeNotification, NSWorkspaceWillSleepNotification,
};
use objc2_foundation::{NSNotification, NSObjectProtocol};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
use uuid::Uuid;
use vless_ipc::{AppConfig, ConfigStore, ConnectionMode, parse_profile_list, write_atomic_0600};
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
use winit::window::WindowId;

use crate::installer;
use crate::settings_ui::{FileFingerprint, file_fingerprint, read_clipboard_utf8};
use crate::supervisor::{RuntimeSupervisor, SupervisorConfig, SupervisorState};
use crate::tray_icons::{
    TrayVisualState, active_engine_inputs_changed, build_macos_icon, format_connect_action_label,
    format_profile_menu_label_raw, format_tray_status_line, format_tray_tooltip,
    is_helper_socket_present,
};

/// Post-wake retry interval if the immediate `RecheckServer` probe runs before Wi-Fi re-associates.
const WAKE_RECHECK_RETRY_DELAY: Duration = Duration::from_secs(3);

/// Custom events delivered via [`EventLoopProxy`] to wake the `ControlFlow::Wait` loop.
#[derive(Debug)]
pub enum AppUserEvent {
    Menu(MenuEvent),
    SupervisorUpdated,
    ConfigReloadRequested,
    SettingsExited,
    HelperInstallFinished(Result<String, String>),
    SystemWillSleep,
    SystemWake,
    TerminateSignal,
}

/// Keeps every `muda` menu item handle alive while attached to the macOS `NSStatusItem`.
struct LiveMenuHandles {
    menu: Menu,
    status_item: MenuItem,
    connect_item: MenuItem,
    mode_off_item: CheckMenuItem,
    mode_proxy_item: CheckMenuItem,
    mode_tun_item: CheckMenuItem,
    #[allow(dead_code)]
    profiles_submenu: Submenu,
    profile_items: Vec<(Uuid, CheckMenuItem)>,
    #[allow(dead_code)]
    empty_profiles_item: Option<MenuItem>,
    import_clipboard_item: MenuItem,
    recheck_item: MenuItem,
    settings_item: MenuItem,
    view_logs_item: MenuItem,
    install_helper_item: MenuItem,
    quit_item: MenuItem,
    #[allow(dead_code)]
    separators: Vec<PredefinedMenuItem>,
}

/// Registers an observer on `NSWorkspace.sharedWorkspace().notificationCenter()` for
/// `NSWorkspaceDidWakeNotification` (`PLAN.md` §5.5).
pub fn observe_wake_notifications(
    on_wake: impl Fn() + Send + Sync + 'static,
) -> Retained<ProtocolObject<dyn NSObjectProtocol>> {
    let workspace = NSWorkspace::sharedWorkspace();
    let center = workspace.notificationCenter();
    let block = RcBlock::new(move |_notif: NonNull<NSNotification>| {
        on_wake();
    });
    // SAFETY: `NSWorkspaceDidWakeNotification` is a valid static AppKit notification name,
    // `on_wake` is `Send + Sync + 'static` so invocation on any posting queue (`queue: None`) is
    // thread-safe, and Foundation retains `block` until the returned observer token is removed.
    unsafe {
        center.addObserverForName_object_queue_usingBlock(
            Some(NSWorkspaceDidWakeNotification),
            None,
            None,
            &block,
        )
    }
}

/// Registers an observer on `NSWorkspace.sharedWorkspace().notificationCenter()` for
/// `NSWorkspaceWillSleepNotification`.
pub fn observe_sleep_notifications(
    on_sleep: impl Fn() + Send + Sync + 'static,
) -> Retained<ProtocolObject<dyn NSObjectProtocol>> {
    let workspace = NSWorkspace::sharedWorkspace();
    let center = workspace.notificationCenter();
    let block = RcBlock::new(move |_notif: NonNull<NSNotification>| {
        on_sleep();
    });
    // SAFETY: `NSWorkspaceWillSleepNotification` is a valid static AppKit notification name,
    // `on_sleep` is `Send + Sync + 'static`, and Foundation retains `block` until removed.
    unsafe {
        center.addObserverForName_object_queue_usingBlock(
            Some(NSWorkspaceWillSleepNotification),
            None,
            None,
            &block,
        )
    }
}

fn remove_workspace_observer(observer: &ProtocolObject<dyn NSObjectProtocol>) {
    let workspace = NSWorkspace::sharedWorkspace();
    let center = workspace.notificationCenter();
    let any_obj: &AnyObject = observer.as_ref();
    // SAFETY: `observer` is the opaque observer token returned by
    // `addObserverForName_object_queue_usingBlock` on this exact `NSNotificationCenter`.
    unsafe {
        center.removeObserver(any_obj);
    }
}

fn focus_running_settings_child(pid: u32) {
    if pid == 0 || pid > i32::MAX as u32 {
        return;
    }
    let pid_t = pid as libc::pid_t;
    if let Some(running_app) = NSRunningApplication::runningApplicationWithProcessIdentifier(pid_t)
    {
        let _ = running_app.activateWithOptions(NSApplicationActivationOptions::ActivateAllWindows);
    }
    // Also notify the `--settings` child via `SIGUSR1` so if its window was minimized to the Dock,
    // `SettingsApp` un-minimizes and focuses its viewport.
    // SAFETY: `kill(pid, SIGUSR1)` with a positive child `pid` signals only that child process;
    // the child registers a `SIGUSR1` listener in `run_settings_window`.
    unsafe {
        let _ = libc::kill(pid_t, libc::SIGUSR1);
    }
}

struct TrayApp {
    initialized: bool,
    has_shut_down: bool,
    store: ConfigStore,
    config: AppConfig,
    last_config_fingerprint: Option<FileFingerprint>,
    supervisor: RuntimeSupervisor,
    proxy: EventLoopProxy<AppUserEvent>,
    icons: HashMap<TrayVisualState, Icon>,
    current_visual: TrayVisualState,
    tray_icon: Option<TrayIcon>,
    menu_handles: Option<LiveMenuHandles>,
    wake_observer: Option<Retained<ProtocolObject<dyn NSObjectProtocol>>>,
    sleep_observer: Option<Retained<ProtocolObject<dyn NSObjectProtocol>>>,
    settings_running: Arc<AtomicBool>,
    settings_child_pid: Arc<AtomicU32>,
    terminate_settings_flag: Arc<AtomicBool>,
    helper_install_running: bool,
    pending_connect_after_helper_install: bool,
    transient_notice: Option<String>,
}

impl TrayApp {
    fn new(
        store: ConfigStore,
        initial_config: AppConfig,
        initial_notice: Option<String>,
        proxy: EventLoopProxy<AppUserEvent>,
    ) -> Result<Self, String> {
        let state_proxy = proxy.clone();
        let mut sup_cfg = SupervisorConfig::new(store.dir().to_path_buf());
        sup_cfg.on_state_change = Some(Arc::new(move |_state| {
            let _ = state_proxy.send_event(AppUserEvent::SupervisorUpdated);
        }));

        let supervisor = RuntimeSupervisor::new(sup_cfg)
            .map_err(|err| format!("failed to initialize engine supervisor runtime: {err}"))?;

        let term_proxy = proxy.clone();
        supervisor.spawn_termination_watcher(move || {
            let _ = term_proxy.send_event(AppUserEvent::TerminateSignal);
        });

        let last_config_fingerprint = file_fingerprint(&store.config_path());

        Ok(Self {
            initialized: false,
            has_shut_down: false,
            store,
            config: initial_config,
            last_config_fingerprint,
            supervisor,
            proxy,
            icons: HashMap::with_capacity(4),
            current_visual: TrayVisualState::Disconnected,
            tray_icon: None,
            menu_handles: None,
            wake_observer: None,
            sleep_observer: None,
            settings_running: Arc::new(AtomicBool::new(false)),
            settings_child_pid: Arc::new(AtomicU32::new(0)),
            terminate_settings_flag: Arc::new(AtomicBool::new(false)),
            helper_install_running: false,
            pending_connect_after_helper_install: false,
            transient_notice: initial_notice,
        })
    }

    fn build_icon_cache(&mut self) -> Result<(), String> {
        for state in [
            TrayVisualState::Disconnected,
            TrayVisualState::Connecting,
            TrayVisualState::Connected,
            TrayVisualState::Error,
        ] {
            let icon = build_macos_icon(state)
                .map_err(|err| format!("failed to build {state:?} menu-bar icon: {err}"))?;
            self.icons.insert(state, icon);
        }
        Ok(())
    }

    fn helper_install_menu_label(&self) -> &'static str {
        if self.helper_install_running {
            "Installing Privileged Helper…"
        } else if is_helper_socket_present(self.supervisor.helper_socket_path()) {
            "Reinstall Privileged Helper…"
        } else {
            "Install Privileged Helper…"
        }
    }

    fn construct_menu_handles(
        &self,
        sup_state: &SupervisorState,
    ) -> Result<LiveMenuHandles, String> {
        let menu = Menu::new();

        let status_text =
            format_tray_status_line(sup_state, &self.config, self.transient_notice.as_deref());
        let status_item = MenuItem::new(status_text, false, None);

        let connect_enabled = sup_state.status != vless_ipc::EngineStatus::Disconnecting;
        let connect_item = MenuItem::new(
            format_connect_action_label(sup_state),
            connect_enabled,
            None,
        );

        let sep_modes = PredefinedMenuItem::separator();
        let mode_off_item = CheckMenuItem::new(
            "Mode: Off",
            true,
            self.config.mode == ConnectionMode::Off,
            None,
        );
        let mode_proxy_item = CheckMenuItem::new(
            "Mode: System Proxy",
            true,
            self.config.mode == ConnectionMode::SystemProxy,
            None,
        );
        let mode_tun_item = CheckMenuItem::new(
            "Mode: TUN",
            true,
            self.config.mode == ConnectionMode::Tun,
            None,
        );

        let sep_profiles = PredefinedMenuItem::separator();
        let profiles_submenu = Submenu::new("Profiles", true);
        let mut profile_items = Vec::with_capacity(self.config.profiles.len());
        let mut empty_profiles_item = None;

        if self.config.profiles.is_empty() {
            let empty_item = MenuItem::new("No Profiles Configured", false, None);
            profiles_submenu
                .append(&empty_item)
                .map_err(|e| format!("failed appending empty profile item: {e}"))?;
            empty_profiles_item = Some(empty_item);
        } else {
            for profile in &self.config.profiles {
                let checked = self.config.selected_profile_id == Some(profile.id);
                // Pass raw unescaped text to `CheckMenuItem::new` because `muda` 0.17.2's macOS
                // `MenuChild::new_check` does not invoke `strip_mnemonic` (unlike `MenuItem::new`).
                let item =
                    CheckMenuItem::new(format_profile_menu_label_raw(profile), true, checked, None);
                profiles_submenu
                    .append(&item)
                    .map_err(|e| format!("failed appending profile menu item: {e}"))?;
                profile_items.push((profile.id, item));
            }
        }

        let sep_profile_import = PredefinedMenuItem::separator();
        let import_clipboard_item = MenuItem::new("Import Profile from Clipboard", true, None);
        profiles_submenu
            .append_items(&[&sep_profile_import, &import_clipboard_item])
            .map_err(|e| format!("failed appending clipboard import menu item: {e}"))?;

        let sep_tools = PredefinedMenuItem::separator();
        let can_recheck = matches!(
            sup_state.status,
            vless_ipc::EngineStatus::Connected | vless_ipc::EngineStatus::Reconnecting
        );
        let recheck_item = MenuItem::new("Re-check Server", can_recheck, None);
        let settings_item = MenuItem::new("Settings…", true, None);
        let view_logs_item = MenuItem::new("View Engine Log…", true, None);
        let install_helper_item = MenuItem::new(
            self.helper_install_menu_label(),
            !self.helper_install_running,
            None,
        );

        let sep_quit = PredefinedMenuItem::separator();
        let quit_item = MenuItem::new("Quit VLESS Tray", true, None);

        menu.append_items(&[
            &status_item,
            &connect_item,
            &sep_modes,
            &mode_off_item,
            &mode_proxy_item,
            &mode_tun_item,
            &sep_profiles,
            &profiles_submenu,
            &sep_tools,
            &recheck_item,
            &settings_item,
            &view_logs_item,
            &install_helper_item,
            &sep_quit,
            &quit_item,
        ])
        .map_err(|e| format!("failed building tray menu: {e}"))?;

        Ok(LiveMenuHandles {
            menu,
            status_item,
            connect_item,
            mode_off_item,
            mode_proxy_item,
            mode_tun_item,
            profiles_submenu,
            profile_items,
            empty_profiles_item,
            import_clipboard_item,
            recheck_item,
            settings_item,
            view_logs_item,
            install_helper_item,
            quit_item,
            separators: vec![
                sep_modes,
                sep_profiles,
                sep_profile_import,
                sep_tools,
                sep_quit,
            ],
        })
    }

    fn rebuild_full_menu(&mut self) {
        let sup_state = self.supervisor.state();
        if let Ok(handles) = self.construct_menu_handles(&sup_state) {
            if let Some(tray) = &self.tray_icon {
                tray.set_menu(Some(Box::new(handles.menu.clone())));
            }
            self.menu_handles = Some(handles);
        }
        self.refresh_status_and_icon(&sup_state);
    }

    fn refresh_status_and_icon(&mut self, sup_state: &SupervisorState) {
        let install_label = self.helper_install_menu_label();
        if let Some(handles) = &self.menu_handles {
            handles.status_item.set_text(format_tray_status_line(
                sup_state,
                &self.config,
                self.transient_notice.as_deref(),
            ));
            handles
                .connect_item
                .set_text(format_connect_action_label(sup_state));
            handles
                .connect_item
                .set_enabled(sup_state.status != vless_ipc::EngineStatus::Disconnecting);
            handles
                .mode_off_item
                .set_checked(self.config.mode == ConnectionMode::Off);
            handles
                .mode_proxy_item
                .set_checked(self.config.mode == ConnectionMode::SystemProxy);
            handles
                .mode_tun_item
                .set_checked(self.config.mode == ConnectionMode::Tun);
            for (pid, item) in &handles.profile_items {
                item.set_checked(self.config.selected_profile_id == Some(*pid));
            }
            let can_recheck = matches!(
                sup_state.status,
                vless_ipc::EngineStatus::Connected | vless_ipc::EngineStatus::Reconnecting
            );
            handles.recheck_item.set_enabled(can_recheck);
            handles.install_helper_item.set_text(install_label);
            handles
                .install_helper_item
                .set_enabled(!self.helper_install_running);
        }

        let next_visual = TrayVisualState::from_engine_status(sup_state.status);
        if let Some(tray) = &self.tray_icon {
            let _ = tray.set_tooltip(Some(format_tray_tooltip(sup_state, &self.config)));
            if next_visual != self.current_visual
                && let Some(icon) = self.icons.get(&next_visual).cloned()
            {
                let _ = tray.set_icon_with_as_template(Some(icon), true);
                self.current_visual = next_visual;
            }
        }
    }

    fn sync_disk_if_modified_before_write(&mut self) {
        let disk_fp = file_fingerprint(&self.store.config_path());
        if disk_fp != self.last_config_fingerprint
            && let Ok(disk_cfg) = self.store.load()
        {
            self.config = disk_cfg;
            self.last_config_fingerprint = disk_fp;
        }
    }

    fn save_config(&mut self) -> Result<(), String> {
        self.store
            .save(&self.config)
            .map_err(|err| err.to_string())?;
        self.last_config_fingerprint = file_fingerprint(&self.store.config_path());
        Ok(())
    }

    fn ensure_selected_profile_if_available(&mut self) -> bool {
        if self.config.selected_profile().is_some() {
            return true;
        }
        if let Some(first) = self.config.profiles.first() {
            self.config.selected_profile_id = Some(first.id);
            let _ = self.save_config();
            return true;
        }
        false
    }

    fn initiate_connect_or_prompt_helper(&mut self) {
        if !is_helper_socket_present(self.supervisor.helper_socket_path()) {
            self.pending_connect_after_helper_install = true;
            self.start_helper_installation();
        } else {
            self.pending_connect_after_helper_install = false;
            self.supervisor.spawn_connect(self.config.clone());
        }
    }

    fn handle_menu_click(&mut self, event_loop: &ActiveEventLoop, id: &MenuId) {
        let Some(handles) = &self.menu_handles else {
            return;
        };

        let connect_id = handles.connect_item.id().clone();
        let off_id = handles.mode_off_item.id().clone();
        let proxy_id = handles.mode_proxy_item.id().clone();
        let tun_id = handles.mode_tun_item.id().clone();
        let import_clipboard_id = handles.import_clipboard_item.id().clone();
        let recheck_id = handles.recheck_item.id().clone();
        let settings_id = handles.settings_item.id().clone();
        let view_logs_id = handles.view_logs_item.id().clone();
        let install_id = handles.install_helper_item.id().clone();
        let quit_id = handles.quit_item.id().clone();
        let matched_profile = handles
            .profile_items
            .iter()
            .find(|(_, item)| item.id() == id)
            .map(|(pid, _)| *pid);

        if id == &connect_id {
            self.transient_notice = None;
            let sup_state = self.supervisor.state();
            if sup_state.is_active() {
                self.pending_connect_after_helper_install = false;
                self.supervisor.spawn_disconnect();
            } else {
                self.sync_disk_if_modified_before_write();
                if !self.ensure_selected_profile_if_available() {
                    self.transient_notice = Some(
                        "No profiles configured — import from Clipboard or open Settings…"
                            .to_string(),
                    );
                    self.refresh_status_and_icon(&sup_state);
                } else if self.config.mode == ConnectionMode::Off {
                    self.transient_notice =
                        Some("Mode is Off — select Mode: System Proxy or Mode: TUN".to_string());
                    self.refresh_status_and_icon(&sup_state);
                } else {
                    self.rebuild_full_menu();
                    self.initiate_connect_or_prompt_helper();
                }
            }
        } else if id == &off_id {
            self.switch_mode(ConnectionMode::Off);
        } else if id == &proxy_id {
            self.switch_mode(ConnectionMode::SystemProxy);
        } else if id == &tun_id {
            self.switch_mode(ConnectionMode::Tun);
        } else if let Some(profile_id) = matched_profile {
            self.select_profile(profile_id);
        } else if id == &import_clipboard_id {
            self.import_profile_from_clipboard();
        } else if id == &recheck_id {
            self.transient_notice = Some("Checking server reachability…".to_string());
            let sup_state = self.supervisor.state();
            self.refresh_status_and_icon(&sup_state);
            self.supervisor.spawn_recheck_server();
        } else if id == &settings_id {
            self.spawn_settings_process();
        } else if id == &view_logs_id {
            self.open_engine_log_in_console();
        } else if id == &install_id {
            self.pending_connect_after_helper_install = false;
            self.start_helper_installation();
        } else if id == &quit_id {
            self.quit_cleanly(event_loop);
        }
    }

    fn switch_mode(&mut self, new_mode: ConnectionMode) {
        self.transient_notice = None;
        self.sync_disk_if_modified_before_write();

        let old_mode = self.config.mode;
        let sup_state = self.supervisor.state();

        if new_mode == ConnectionMode::Off {
            self.pending_connect_after_helper_install = false;
            self.config.mode = ConnectionMode::Off;
            if let Err(err) = self.save_config() {
                self.transient_notice = Some(format!("Failed saving mode: {err}"));
            }
            self.refresh_status_and_icon(&sup_state);
            if sup_state.is_active() {
                self.supervisor.spawn_disconnect();
            }
            return;
        }

        // Switching to `SystemProxy` or `Tun`: verify a profile is available first.
        if !self.ensure_selected_profile_if_available() {
            self.config.mode = ConnectionMode::Off;
            let _ = self.save_config();
            self.transient_notice = Some(
                "No profiles configured — import from Clipboard or open Settings…".to_string(),
            );
            self.refresh_status_and_icon(&sup_state);
            return;
        }

        self.config.mode = new_mode;
        if let Err(err) = self.save_config() {
            self.transient_notice = Some(format!("Failed saving mode: {err}"));
        }
        self.refresh_status_and_icon(&sup_state);

        // Connect immediately when switching into an active mode (or switching between Proxy/TUN).
        if old_mode != new_mode || !sup_state.is_active() {
            self.initiate_connect_or_prompt_helper();
        }
    }

    fn select_profile(&mut self, profile_id: Uuid) {
        self.transient_notice = None;
        self.sync_disk_if_modified_before_write();

        let changed = self.config.selected_profile_id != Some(profile_id);
        self.config.selected_profile_id = Some(profile_id);
        if let Err(err) = self.save_config() {
            self.transient_notice = Some(format!("Failed saving profile selection: {err}"));
        }

        let sup_state = self.supervisor.state();
        self.refresh_status_and_icon(&sup_state);

        if changed && sup_state.is_active() && self.config.mode != ConnectionMode::Off {
            self.initiate_connect_or_prompt_helper();
        }
    }

    fn import_profile_from_clipboard(&mut self) {
        self.sync_disk_if_modified_before_write();

        let raw_text = match read_clipboard_utf8() {
            Ok(t) => t,
            Err(err) => {
                self.transient_notice = Some(err);
                let sup_state = self.supervisor.state();
                self.refresh_status_and_icon(&sup_state);
                return;
            }
        };

        let imports = match parse_profile_list(raw_text.trim()) {
            Ok(ok) => ok,
            Err(err) => {
                self.transient_notice = Some(format!("Clipboard import failed: {err}"));
                let sup_state = self.supervisor.state();
                self.refresh_status_and_icon(&sup_state);
                return;
            }
        };

        let new_id = imports[0].profile.id;
        let new_name = imports[0].profile.name.clone();
        let first_warning = imports
            .iter()
            .flat_map(|entry| &entry.warnings)
            .next()
            .cloned();
        let old_count = self.config.profiles.len();
        let prev_selected = self.config.selected_profile_id;
        self.config
            .profiles
            .extend(imports.into_iter().map(|entry| entry.profile));
        self.config.selected_profile_id = Some(new_id);

        if let Err(err) = self.save_config() {
            self.config.profiles.truncate(old_count);
            self.config.selected_profile_id = prev_selected;
            self.transient_notice = Some(format!("Failed saving imported profile: {err}"));
            let sup_state = self.supervisor.state();
            self.refresh_status_and_icon(&sup_state);
            return;
        }

        self.transient_notice = if let Some(first_warn) = first_warning {
            Some(format!("Imported \"{new_name}\" — Warning: {first_warn}"))
        } else {
            Some(format!("Imported and selected \"{new_name}\""))
        };
        self.rebuild_full_menu();

        let sup_state = self.supervisor.state();
        if sup_state.is_active() && self.config.mode != ConnectionMode::Off {
            self.initiate_connect_or_prompt_helper();
        }
    }

    fn open_engine_log_in_console(&mut self) {
        let log_path = self.supervisor.engine_log_path();
        if !log_path.exists()
            && let Err(err) = write_atomic_0600(&log_path, b"")
        {
            self.transient_notice = Some(format!("Cannot initialize engine.log: {err}"));
            let sup_state = self.supervisor.state();
            self.refresh_status_and_icon(&sup_state);
            return;
        }

        if let Err(err) = Command::new("/usr/bin/open")
            .args(["-a", "Console"])
            .arg(&log_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            self.transient_notice = Some(format!("Failed opening Console.app: {err}"));
            let sup_state = self.supervisor.state();
            self.refresh_status_and_icon(&sup_state);
        }
    }

    fn reload_config_from_disk(&mut self) {
        let disk_fp = file_fingerprint(&self.store.config_path());
        match self.store.load() {
            Ok(new_cfg) => {
                let old_cfg = self.config.clone();
                let inputs_changed = active_engine_inputs_changed(&old_cfg, &new_cfg);
                self.config = new_cfg;
                self.last_config_fingerprint = disk_fp;
                self.transient_notice = None;
                self.rebuild_full_menu();

                let sup_state = self.supervisor.state();
                if inputs_changed && sup_state.is_active() {
                    if self.config.mode == ConnectionMode::Off
                        || self.config.selected_profile().is_none()
                    {
                        self.supervisor.spawn_disconnect();
                    } else {
                        self.initiate_connect_or_prompt_helper();
                    }
                }
            }
            Err(err) => {
                self.transient_notice = Some(format!("Config reload error: {err}"));
                let sup_state = self.supervisor.state();
                self.refresh_status_and_icon(&sup_state);
            }
        }
    }

    fn spawn_settings_process(&mut self) {
        if self.settings_running.swap(true, Ordering::AcqRel) {
            // `--settings` child is already open: bring its window to the front instead of
            // spawning duplicate GPU windows.
            focus_running_settings_child(self.settings_child_pid.load(Ordering::Acquire));
            return;
        }

        let exe = match std::env::current_exe() {
            Ok(exe) => exe,
            Err(err) => {
                self.settings_running.store(false, Ordering::Release);
                self.transient_notice = Some(format!("Cannot locate vless-tray binary: {err}"));
                let sup_state = self.supervisor.state();
                self.refresh_status_and_icon(&sup_state);
                return;
            }
        };

        let config_dir = self.store.dir().to_path_buf();
        let config_path = self.store.config_path();
        let child_res = Command::new(&exe)
            .arg("--settings")
            .arg("--config-dir")
            .arg(&config_dir)
            .stdin(Stdio::null())
            .spawn();

        let mut child = match child_res {
            Ok(c) => c,
            Err(err) => {
                self.settings_running.store(false, Ordering::Release);
                self.transient_notice = Some(format!("Failed opening Settings: {err}"));
                let sup_state = self.supervisor.state();
                self.refresh_status_and_icon(&sup_state);
                return;
            }
        };

        self.settings_child_pid.store(child.id(), Ordering::Release);

        let running_flag = Arc::clone(&self.settings_running);
        let pid_slot = Arc::clone(&self.settings_child_pid);
        let terminate_flag = Arc::clone(&self.terminate_settings_flag);
        let proxy = self.proxy.clone();

        // Short-lived watcher thread that lives strictly while `--settings` is open, checking
        // `config.json` `(dev, ino, len, mtime)` fingerprint and child exit so idle CPU returns to
        // 0% immediately when Settings is closed.
        std::thread::Builder::new()
            .name("vless-settings-watch".to_string())
            .spawn(move || {
                let mut last_fp = file_fingerprint(&config_path);
                loop {
                    if terminate_flag.load(Ordering::Acquire) {
                        let _ = child.kill();
                        let _ = child.wait();
                        break;
                    }

                    let current_fp = file_fingerprint(&config_path);
                    if current_fp != last_fp {
                        last_fp = current_fp;
                        let _ = proxy.send_event(AppUserEvent::ConfigReloadRequested);
                    }

                    match child.try_wait() {
                        Ok(Some(_status)) => {
                            let final_fp = file_fingerprint(&config_path);
                            if final_fp != last_fp {
                                let _ = proxy.send_event(AppUserEvent::ConfigReloadRequested);
                            }
                            break;
                        }
                        Ok(None) => {
                            std::thread::sleep(Duration::from_millis(200));
                        }
                        Err(_) => break,
                    }
                }
                pid_slot.store(0, Ordering::Release);
                running_flag.store(false, Ordering::Release);
                let _ = proxy.send_event(AppUserEvent::SettingsExited);
            })
            .ok();
    }

    fn start_helper_installation(&mut self) {
        if self.helper_install_running {
            return;
        }
        self.helper_install_running = true;
        self.transient_notice = Some("Requesting administrator permission for helper…".to_string());
        let sup_state = self.supervisor.state();
        self.refresh_status_and_icon(&sup_state);

        let proxy = self.proxy.clone();
        std::thread::Builder::new()
            .name("vless-install-helper".to_string())
            .spawn(move || {
                let outcome =
                    installer::run_install_helper_default().map_err(|err| err.to_string());
                let _ = proxy.send_event(AppUserEvent::HelperInstallFinished(outcome));
            })
            .ok();
    }

    fn shutdown_idempotent(&mut self) {
        if self.has_shut_down {
            return;
        }
        self.has_shut_down = true;
        self.terminate_settings_flag.store(true, Ordering::Release);

        if let Some(observer) = self.wake_observer.take() {
            remove_workspace_observer(&observer);
        }
        if let Some(observer) = self.sleep_observer.take() {
            remove_workspace_observer(&observer);
        }

        MenuEvent::set_event_handler::<fn(MenuEvent)>(None);

        // Synchronously await engine disconnect so `vless-tray-helper` restores routes, DNS, and
        // system proxies before `vless-tray` exits (`PLAN.md` §4).
        self.supervisor.shutdown();

        self.tray_icon = None;
        self.menu_handles = None;
    }

    fn quit_cleanly(&mut self, event_loop: &ActiveEventLoop) {
        self.shutdown_idempotent();
        event_loop.exit();
    }
}

impl ApplicationHandler<AppUserEvent> for TrayApp {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        event_loop.set_control_flow(ControlFlow::Wait);
        if self.initialized {
            return;
        }
        self.initialized = true;

        if let Err(err) = self.build_icon_cache() {
            eprintln!("vless-tray: {err}");
            event_loop.exit();
            return;
        }

        let sup_state = self.supervisor.state();
        let initial_visual = TrayVisualState::from_engine_status(sup_state.status);
        let Some(initial_icon) = self.icons.get(&initial_visual).cloned() else {
            event_loop.exit();
            return;
        };

        let handles = match self.construct_menu_handles(&sup_state) {
            Ok(h) => h,
            Err(err) => {
                eprintln!("vless-tray: {err}");
                event_loop.exit();
                return;
            }
        };

        let tray = match TrayIconBuilder::new()
            .with_menu(Box::new(handles.menu.clone()))
            .with_tooltip(format_tray_tooltip(&sup_state, &self.config))
            .with_icon(initial_icon)
            .with_icon_as_template(true)
            .with_menu_on_left_click(true)
            .build()
        {
            Ok(t) => t,
            Err(err) => {
                eprintln!("vless-tray: failed creating macOS status item: {err}");
                event_loop.exit();
                return;
            }
        };

        let menu_proxy = self.proxy.clone();
        MenuEvent::set_event_handler(Some(move |event| {
            let _ = menu_proxy.send_event(AppUserEvent::Menu(event));
        }));

        let wake_proxy = self.proxy.clone();
        self.wake_observer = Some(observe_wake_notifications(move || {
            let _ = wake_proxy.send_event(AppUserEvent::SystemWake);
        }));

        let sleep_proxy = self.proxy.clone();
        self.sleep_observer = Some(observe_sleep_notifications(move || {
            let _ = sleep_proxy.send_event(AppUserEvent::SystemWillSleep);
        }));

        self.current_visual = initial_visual;
        self.menu_handles = Some(handles);
        self.tray_icon = Some(tray);
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: AppUserEvent) {
        event_loop.set_control_flow(ControlFlow::Wait);

        match event {
            AppUserEvent::Menu(menu_event) => {
                self.handle_menu_click(event_loop, &menu_event.id);
            }
            AppUserEvent::SupervisorUpdated => {
                let sup_state = self.supervisor.state();
                if sup_state.status == vless_ipc::EngineStatus::Connected
                    || sup_state.status == vless_ipc::EngineStatus::Error
                    || sup_state.last_server_check.is_some()
                {
                    self.transient_notice = None;
                }
                self.refresh_status_and_icon(&sup_state);
            }
            AppUserEvent::ConfigReloadRequested | AppUserEvent::SettingsExited => {
                self.reload_config_from_disk();
            }
            AppUserEvent::HelperInstallFinished(result) => {
                self.helper_install_running = false;
                let auto_connect = self.pending_connect_after_helper_install;
                self.pending_connect_after_helper_install = false;

                match result {
                    Ok(msg) => {
                        if auto_connect
                            && self.config.mode != ConnectionMode::Off
                            && self.config.selected_profile().is_some()
                        {
                            self.transient_notice = None;
                            self.supervisor.spawn_connect(self.config.clone());
                        } else {
                            self.transient_notice = Some(format!("Helper ready: {msg}"));
                        }
                    }
                    Err(err) => {
                        self.transient_notice = Some(format!("Helper install: {err}"));
                    }
                }
                let sup_state = self.supervisor.state();
                self.refresh_status_and_icon(&sup_state);
            }
            AppUserEvent::SystemWillSleep => {
                // Nothing runs or polls during sleep; `vless-engine` dials fresh per flow on wake.
            }
            AppUserEvent::SystemWake => {
                self.supervisor.spawn_wake_recheck(WAKE_RECHECK_RETRY_DELAY);
            }
            AppUserEvent::TerminateSignal => {
                self.quit_cleanly(event_loop);
            }
        }
    }

    fn window_event(
        &mut self,
        event_loop: &ActiveEventLoop,
        _window_id: WindowId,
        _event: WindowEvent,
    ) {
        event_loop.set_control_flow(ControlFlow::Wait);
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        // Enforce 0% idle CPU: never poll timers on the menu-bar event loop (`PLAN.md` §7).
        event_loop.set_control_flow(ControlFlow::Wait);
    }

    fn exiting(&mut self, _event_loop: &ActiveEventLoop) {
        // Handles external macOS termination (`applicationWillTerminate:` / AppleScript `quit` /
        // system logout) identically to clicking `Quit VLESS Tray`.
        self.shutdown_idempotent();
    }
}

/// Entrypoint for the macOS menu-bar process (`vless-tray` with no subcommand).
pub fn run_tray_app(config_dir: PathBuf) -> Result<(), String> {
    let store = ConfigStore::new(config_dir);
    let (initial_config, initial_notice) = match store.load() {
        Ok(cfg) => (cfg, None),
        Err(err) => (
            AppConfig::default(),
            Some(format!("Config load error: {err}")),
        ),
    };

    let mut builder = EventLoop::<AppUserEvent>::with_user_event();
    builder
        .with_activation_policy(ActivationPolicy::Accessory)
        .with_default_menu(false)
        .with_activate_ignoring_other_apps(false);
    let event_loop = builder
        .build()
        .map_err(|err| format!("failed building macOS menu-bar EventLoop: {err}"))?;
    event_loop.set_control_flow(ControlFlow::Wait);

    let proxy = event_loop.create_proxy();
    let mut app = TrayApp::new(store, initial_config, initial_notice, proxy)?;
    event_loop
        .run_app(&mut app)
        .map_err(|err| format!("menu-bar EventLoop error: {err}"))
}
