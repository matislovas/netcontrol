
use crate::args;
use clap::ArgMatches;
use log::{debug, error, info, trace, warn, LevelFilter, SetLoggerError};
use std::fs;
use std::io;
use std::path::Path;
use log4rs::{
    append::{
        console::{ConsoleAppender, Target},
        file::FileAppender,
    },
    config::{Appender, Config, Root}
};

fn create_log_file(path: &str) -> io::Result<fs::File> {
    if Path::new(path).exists() {
        fs::remove_file(path)?;
    }
      
    fs::File::create(path)
} 

pub fn init(arguments: &ArgMatches) -> Result<(), SetLoggerError> {
    let mut config_builder = Config::builder();

    let mut level = log::LevelFilter::Warn;

    let mut file_logging = false;

    if !args::get_silent(arguments) {
        level = match args::get_verbosity(arguments) {
            0 => log::LevelFilter::Warn,
            1 => log::LevelFilter::Info,
            2 => log::LevelFilter::Debug,
            3 | _ => log::LevelFilter::Trace,
        }
    } else {
        level = log::LevelFilter::Off;
    }

    let stdout = ConsoleAppender::builder().target(Target::Stdout).build();
    
    config_builder = config_builder.appender(Appender::builder().build("stdout", Box::new(stdout)));

    match args::get_logfile(arguments) {
        Some(filepath) => {
            file_logging = true;

            create_log_file(filepath).unwrap();

            let logfile = FileAppender::builder().build(filepath).unwrap();

            config_builder = config_builder.appender(Appender::builder().build("logfile", Box::new(logfile)));
        },
        None => ()
    }

    let mut root_builder = Root::builder().appender("stdout");

    if file_logging {
        root_builder = root_builder.appender("logfile");
    }

    let config = config_builder.build(root_builder.build(level)).unwrap();

    log4rs::init_config(config)?;

    Ok(())
}
