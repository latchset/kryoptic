use std::fs::File;

use simplelog::{Config, LevelFilter, SimpleLogger, WriteLogger};

#[used]
#[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array"))]
pub static INITIALIZE: extern "C" fn() = kryoptic_log_init;

/// Initializes a simple logger for tracing purposes based on the values of
/// the environment variable KRYOPTIC_TRACE:
/// - stdout -> logs to standard output
/// - file -> any other value is interpreted as a file name to log into
/// - NOT PRESENT -> No tracing is initialized
/// If the logger initialization encounters an error, (for example the log
/// file can't be opened) no tracing is available and no error is reported.
///
/// Additionally the log level can be selected with the environment variable
/// KRYOPTIC_TRACE_LEVEL
/// It defaults to LevelFilter::Error.
/// Valid values are: off, error, warn, info, debug, trace.
/// Any incorrect value triggers the highest logging level: LevelFilter::Trace

#[unsafe(no_mangle)]
pub extern "C" fn kryoptic_log_init() {
    let level = match std::env::var("KRYOPTIC_TRACE_LEVEL") {
        Err(_) => LevelFilter::Error,
        Ok(l) => match l.as_str() {
            "off" => LevelFilter::Off,
            "error" => LevelFilter::Error,
            "warn" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Trace,
        },
    };
    match std::env::var("KRYOPTIC_TRACE") {
        Err(_) => return,
        Ok(t) => match t.as_str() {
            "stdout" => {
                let _ = SimpleLogger::init(level, Config::default());
            }
            file_name => {
                let file = match File::create(file_name) {
                    Ok(w) => w,
                    Err(_) => return,
                };
                let _ = WriteLogger::init(level, Config::default(), file);
            }
        },
    }
}

#[test]
pub fn test_init() {
    kryoptic_log_init();
}
