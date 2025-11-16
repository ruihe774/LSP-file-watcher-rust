use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::io::{BufWriter, Write};
use std::mem;
use std::path::{self, PathBuf};
use std::process::exit;

use glob::Pattern;
use notify::Watcher;
use serde::Deserialize;

fn parent_died() -> ! {
    eprintln!("parent process died");
    exit(1);
}

#[cfg(target_os = "linux")]
fn parent_process_watchdog() {
    use rustix::event::{poll, PollFd, PollFlags};
    use rustix::io::Errno;
    use rustix::process::{getppid, pidfd_open, PidfdFlags};

    let Some(ppid) = getppid() else {
        parent_died();
    };

    let Ok(ppid_fd) = pidfd_open(ppid, PidfdFlags::empty()) else {
        parent_died();
    };

    let mut fds = [PollFd::new(&ppid_fd, PollFlags::IN)];

    loop {
        match poll(&mut fds, -1) {
            Ok(_) => parent_died(),
            Err(Errno::INTR) => continue,
            Err(e) => panic!("poll failed: {e:?}"),
        }
    }
}

#[cfg(windows)]
fn parent_process_watchdog() {
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, PROCESSINFOCLASS};
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, WaitForSingleObject, INFINITE, PROCESS_ACCESS_RIGHTS,
    };

    let mut info = [0usize; 6];
    let mut r_len = 0;
    assert!(unsafe {
        NtQueryInformationProcess(
            GetCurrentProcess(),
            PROCESSINFOCLASS(0),
            info.as_mut_ptr() as _,
            (size_of::<usize>() * 6) as _,
            &raw mut r_len,
        )
    }
    .is_ok());
    assert_eq!(r_len as usize, size_of::<usize>() * 6);

    let ppid = info[5] as u32;
    let Ok(pph) = (unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS(0x00100000), false, ppid) }) else {
        parent_died();
    };

    let _ = unsafe { WaitForSingleObject(pph, INFINITE) };
    parent_died();
}

#[cfg(target_os = "linux")]
fn enter_efficiency_mode() {
    use rustix::process::{sched_setscheduler, SchedParam, SchedPolicy};

    let _ = sched_setscheduler(None, SchedPolicy::Batch, &SchedParam::default());
}

#[cfg(windows)]
fn enter_efficiency_mode() {
    use windows::Win32::System::Threading::{
        GetCurrentProcess, ProcessPowerThrottling, SetProcessInformation,
        PROCESS_POWER_THROTTLING_CURRENT_VERSION, PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION, PROCESS_POWER_THROTTLING_STATE,
    };

    let info = PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED
            | PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
        StateMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED
            | PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
    };
    let _ = unsafe {
        SetProcessInformation(
            GetCurrentProcess(),
            ProcessPowerThrottling,
            &raw const info as _,
            size_of::<PROCESS_POWER_THROTTLING_STATE>() as _,
        )
    };
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum EventType {
    Create,
    Change,
    Delete,
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventType::Create => "create",
            EventType::Change => "change",
            EventType::Delete => "delete",
        }
        .fmt(f)
    }
}

#[derive(Debug, Deserialize)]
struct Register {
    cwd: String,
    events: Vec<EventType>,
    ignores: Vec<String>,
    patterns: Vec<String>,
    uid: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Request {
    Register(Register),
    Unregister(usize),
}

#[derive(Debug)]
struct WatcherConfig {
    root: PathBuf,
    events: Vec<EventType>,
    ignores: Vec<Pattern>,
    patterns: Vec<Pattern>,
    prefixes: Vec<PathBuf>,
    uid: usize,
}

impl WatcherConfig {
    fn new(reg: Register) -> WatcherConfig {
        let root = path::absolute(reg.cwd).unwrap();

        fn make_absolute_paths<'a>(
            cwd: &'a PathBuf,
            paths: &'a Vec<String>,
        ) -> impl Iterator<Item = PathBuf> + use<'a> {
            paths.iter().map(move |path| {
                if cfg!(windows) {
                    path::absolute(cwd.join(path.replace("/", "\\"))).unwrap()
                } else {
                    path::absolute(cwd.join(path)).unwrap()
                }
            })
        }

        let paths_to_patterns = |paths: &Vec<String>| {
            make_absolute_paths(&root, paths)
                .filter_map(|path| {
                    Pattern::new(path.to_string_lossy().as_ref()).map_or_else(
                        |e| {
                            eprintln!("invalid glob pattern: {e:?}");
                            None
                        },
                        |pat| Some(pat),
                    )
                })
                .collect()
        };

        let prefixes: Vec<_> = make_absolute_paths(&root, &reg.patterns).collect();
        let patterns = paths_to_patterns(&reg.patterns);
        let ignores = paths_to_patterns(&reg.ignores);

        let uid = reg.uid;
        let events = reg.events;

        WatcherConfig {
            root,
            events,
            ignores,
            patterns,
            prefixes,
            uid,
        }
    }
}

fn event_handler(event: notify::Result<notify::Event>, config: &WatcherConfig) {
    use notify::event::{CreateKind, ModifyKind, RemoveKind, RenameMode};
    use notify::EventKind;

    let event = match event {
        Ok(event) => event,
        Err(e) => {
            eprintln!("watcher error: {e:?}");
            return;
        }
    };
    let events = [event];

    let mut stdout = BufWriter::new(io::stdout().lock());
    let mut written = false;
    for event in events {
        let event_type = match event.kind {
            EventKind::Create(create) if matches!(create, CreateKind::File) => EventType::Create,
            EventKind::Remove(remove) if matches!(remove, RemoveKind::File) => EventType::Delete,
            EventKind::Modify(modify) => match modify {
                ModifyKind::Name(rename) if matches!(rename, RenameMode::From) => EventType::Delete,
                ModifyKind::Name(rename) if matches!(rename, RenameMode::To) => EventType::Create,
                ModifyKind::Data(_) | ModifyKind::Metadata(_) => EventType::Change,
                _ => continue,
            },
            _ => continue,
        };

        if !config.events.contains(&event_type) {
            continue;
        }

        let options = glob::MatchOptions {
            case_sensitive: true,
            require_literal_separator: true,
            require_literal_leading_dot: true,
        };

        for path in event.paths.iter() {
            if config
                .patterns
                .iter()
                .all(|pattern| !pattern.matches_path_with(&path, options))
                && config
                    .prefixes
                    .iter()
                    .all(|prefix| !path.starts_with(prefix))
                || config
                    .ignores
                    .iter()
                    .any(|ignore| ignore.matches_path_with(&path, options))
            {
                continue;
            }

            let path = path.to_string_lossy();

            writeln!(stdout, "{}:{}:{}", config.uid, event_type, path.as_ref()).unwrap();
            written = true;
        }
    }
    if written {
        writeln!(stdout, "<flush>").unwrap();
        stdout.flush().unwrap();
    }
}

fn create_watcher(reg: Register) -> notify::Result<notify::RecommendedWatcher> {
    let mut config = WatcherConfig::new(reg);
    let root = mem::take(&mut config.root);
    notify::recommended_watcher(move |event| event_handler(event, &config)).and_then(
        |mut watcher| {
            watcher
                .watch(&root, notify::RecursiveMode::Recursive)
                .map(|()| watcher)
        },
    )
}

fn main() {
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    compile_error!("unsupported platform");

    #[cfg(any(target_os = "linux", windows))]
    {
        enter_efficiency_mode();
        drop(std::thread::spawn(parent_process_watchdog));
    }

    let mut watchers = BTreeMap::new();

    for input in io::stdin().lines() {
        let input = input.expect("failed to read from stdin");
        let request: Request = serde_json::from_str(&input).expect("failed to parse input");

        match request {
            Request::Register(reg) => match watchers.entry(reg.uid) {
                Entry::Occupied(_) => eprintln!("watcher with ID {} already exists", reg.uid),
                Entry::Vacant(entry) => match create_watcher(reg) {
                    Ok(watcher) => {
                        entry.insert(watcher);
                    }
                    Err(e) => {
                        eprintln!("failed to watch on path: {e:?}");
                    }
                },
            },
            Request::Unregister(uid) => {
                if watchers.remove(&uid).is_none() {
                    eprintln!("watcher with ID {uid} not found");
                }
            }
        }
    }

    exit(0);
}
