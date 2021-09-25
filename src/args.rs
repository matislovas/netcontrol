
use clap::{App,Arg,ArgMatches,crate_version};

pub fn init<'a>() -> ArgMatches<'a> {
    App::new("netcontrol")
        .version(crate_version!())
        .about("IPv4 network proxy for accounting")
        .author("Matas Misiunas <mr.matas.misiunas@gmail.com>")
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .required(true)
            .value_name("FILE_PATH")
            .help("Config file path")
            .takes_value(true))
        .arg(Arg::with_name("log")
            .short("l")
            .long("log")
            .required(false)
            .value_name("FILE_PATH")
            .help("Log file path")
            .takes_value(true))
        .arg(Arg::with_name("v")
            .required(false)
            .short("v")
            .multiple(true)
            .help("Log verbosity (v or vv or vvv)"))
        .arg(Arg::with_name("silent")
            .required(false)
            .short("s")
            .long("silent")
            .help("No output to stdout"))
        .get_matches()
}

// This can't error, since it is ".required(true)"
pub fn get_config<'a>(matches: &'a ArgMatches<'a>) -> &'a str {
    matches.value_of("config").unwrap()
}

pub fn get_logfile<'a>(matches: &'a ArgMatches<'a>) -> Option<&'a str> {
    matches.value_of("log")
}

pub fn get_verbosity<'a>(matches: &ArgMatches<'a>) -> u32 {
    matches.occurrences_of("v") as u32
}

pub fn get_silent<'a>(matches: &ArgMatches<'a>) -> bool {
    matches.is_present("silent")
}
