
mod args;
mod logging;
mod config;
mod netfilter;
mod timer;

use clap::ArgMatches;
use log;
use std::{os::raw::c_int, thread};
use signal_hook::{consts::*, iterator::Signals};


#[derive(Debug)]
pub enum StartupErr {
    ConfigFileLoadErr(config::ParseConfigError),
    LoggerError(String),
    ConfigErr(String)
}

impl From<config::ParseConfigError> for StartupErr {
    fn from(e: config::ParseConfigError) -> Self {
        StartupErr::ConfigFileLoadErr(e)
    }
}

const SIGNALS: &[c_int] = &[
    SIGTERM, SIGQUIT, SIGINT, SIGTSTP, SIGWINCH, SIGHUP, SIGCHLD, SIGCONT,
];


fn main() {
    let mut signals = Signals::new(SIGNALS).unwrap();

    thread::spawn(move || {
        for sig in signals.forever() {
            netfilter::deinit().unwrap();
            std::process::exit(0);
        }
    });

    let arguments = args::init();

    match run(&arguments) {
        Ok(_) => log::info!("Stopped!"),
        Err(StartupErr::ConfigFileLoadErr(err)) => {
            log::error!("Failed to load config file. Error: {:?}", err);
            std::process::exit(1);
        },
        Err(StartupErr::LoggerError(err)) => {
            log::error!("Failed to init logger. Error: {:?}", err);
            std::process::exit(1);
        },
        Err(StartupErr::ConfigErr(err)) => {
            log::error!("{}", err);
            std::process::exit(1);
        },
    }
}


fn run(arguments: &ArgMatches) -> Result<(), StartupErr> {    
    let config = config::Config::new_from_file(
        args::get_config(&arguments)).unwrap();
  
    logging::init(&arguments)
        .or_else(|e| Err(
            StartupErr::LoggerError(
                e.to_string())))?;
    
    log::info!("Starting ...");

    netfilter::init(&config).unwrap();

    // nflog::init(&mut queue).unwrap();

    // util::setup_metrics(&config);
  
    // update_process_limits(&config)?;
  
    // let workers = init_workers(&config)?;
  
    // let command_socket_path = config.command_socket_path();
  
    // this could be transformed into a new StartupError that contains std::io::Error
    // if let Err(e) = command::start(config, command_socket_path, workers) {
    //     error!("could not start worker: {:?}", e);
    // }

    netfilter::run();
  
    Ok(())
}
