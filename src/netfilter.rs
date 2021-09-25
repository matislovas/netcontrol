
use byte_unit::Byte;
use ipnetwork::Ipv4Network;
use log::{debug, error, info, trace, warn};
use nftnl::{
    nft_expr,
    nftnl_sys::libc,
    Batch,
    Chain,
    ChainType,
    FinalizedBatch,
    ProtoFamily,
    Rule,
    expr::RejectionType,
    Table,
    Quota,
    QuotaType,
    expr::TcpFlags as TcpFlags
};
use nflog;
use once_cell::unsync::OnceCell;
use std::{
    collections::HashMap,
    ffi::CString,
    io,
    time::Duration,
};
use crate::{
    config::{
        accnt::Accounting,
        Config,
        ToQuota,
    },
    timer::ConnTimer,
};


const TABLE_NAME: &str = "netcontrol";
const DATA_IN_CHAIN_NAME: &str = "data_qt-in";
const DATA_OUT_CHAIN_NAME: &str = "data_qt-out";
const TIME_IN_CHAIN_NAME: &str = "time_qt-in";
const TIME_OUT_CHAIN_NAME: &str = "time_qt-out";

const DATA_LOG_PREFIX: &str = "dq_";
const TIME_LOG_PREFIX: &str = "tq_";
const TIME_START_LOG_PREFIX: &str = "start_";
const TIME_FIN_LOG_PREFIX: &str = "fin_";

pub const DATA_QUOTA_NUM: u16 = 0;
pub const TIME_QUOTA_NUM: u16 = 1;

type LimitEntryName<'a> = &'a str;
type ChainName<'a> = &'a str;

#[derive(Debug)]
pub struct NfHandle<'a> {
    pub table: Table,
    pub chains: HashMap<ChainName<'a>, Chain<'a>>,
    pub log: NflogHandle<'a>,

    pub time_entries: HashMap<LimitEntryName<'a>, NfTimeLimit<'a>>,
    pub data_entries: HashMap<LimitEntryName<'a>, NfDataLimit<'a>>,
}

#[derive(Debug)]
pub struct NflogHandle<'a> {
    pub groups: Vec<nflog::Group<'a>>,
    pub queue: nflog::Queue,
}

impl NfHandle<'_> {
    fn new(table_name: &str) -> NfHandle {
        NfHandle {
            table: Table::new(&CString::new(table_name).unwrap(), ProtoFamily::Ipv4),
            chains: HashMap::new(),
            log: NflogHandle::new(),
            time_entries: HashMap::new(),
            data_entries: HashMap::new(),
        }
    }

    pub fn get() -> &'static mut NfHandle<'static> {
        unsafe { HANDLE_INSTANCE.get_mut().expect("nfhandle is not initialized") }
    }
}

impl<'a> NflogHandle<'a> {
    fn new() -> NflogHandle<'a> {
        let handle = NflogHandle {
            groups: Vec::new(),
            queue: nflog::Queue::open().unwrap(),
        };

        // Lib manual says that this procedure is needed ...
        let _ = handle.queue.unbind(libc::AF_INET);

        handle.queue.bind(libc::AF_INET).unwrap();

        handle
    }
}

#[derive(Debug)]
struct TimeLimitRuleset<'a> {
    // Rule for "SYN & ACK" for incoming traffic (start conn)
    start: Rule<'a>,
    // Rule for "FIN | RST" for incoming traffic (drop conn)
    in_fin: Rule<'a>,
    // Rule for "FIN | RST" for outgoing traffic (drop conn)
    out_fin: Rule<'a>,
    // Rules for "Drop with RST" for input and output traffic
    block_in: Rule<'a>,
    block_out: Rule<'a>,
}

#[derive(Debug)]
struct DataLimitRuleset<'a> {
    // Rule for accounting quota and blocking afterwards
    block: Rule<'a>,
    // Rule for informing userspace for quota overflows
    log: Rule<'a>,
}

impl TimeLimitRuleset<'_> {
    fn new<'a>(out_chain: &'a Chain, in_chain: &'a Chain, ip_: &Ipv4Network, name: &'a str) -> TimeLimitRuleset<'a> {
        let ip = ip_.clone();
        let mut ruleset = TimeLimitRuleset {
            start: Rule::new(&in_chain),
            in_fin: Rule::new(&in_chain),
            out_fin: Rule::new(&out_chain),
            block_in: Rule::new(&in_chain),
            block_out: Rule::new(&out_chain),
        };

        // Input rule for connection start
        ruleset.start.add_expr(&nft_expr!(meta l4proto));
        ruleset.start.add_expr(&nft_expr!(cmp == libc::IPPROTO_TCP as u8));

        ruleset.start.add_expr(&nft_expr!(payload ipv4 saddr));
        ruleset.start.add_expr(&nft_expr!(bitwise mask ip.mask(), xor 0));
        ruleset.start.add_expr(&nft_expr!(cmp == ip.ip()));

        ruleset.start.add_expr(&nft_expr!(payload tcp flags));
        ruleset.start.add_expr(&nft_expr!(bitwise mask (TcpFlags::SYN | TcpFlags::ACK), xor (0 as u8)));
        ruleset.start.add_expr(&nft_expr!(cmp == (TcpFlags::SYN | TcpFlags::ACK)));

        ruleset.start.add_expr(&nft_expr!(
            log .group(TIME_QUOTA_NUM)
                .prefix(&CString::new(format!("{}{}", TIME_START_LOG_PREFIX, name.to_owned())).unwrap()) 
            )
        );

        // Input rule for connection end
        ruleset.in_fin.add_expr(&nft_expr!(meta l4proto));
        ruleset.in_fin.add_expr(&nft_expr!(cmp == libc::IPPROTO_TCP as u8));

        ruleset.in_fin.add_expr(&nft_expr!(payload ipv4 saddr));
        ruleset.in_fin.add_expr(&nft_expr!(bitwise mask ip.mask(), xor 0));
        ruleset.in_fin.add_expr(&nft_expr!(cmp == ip.ip()));

        ruleset.in_fin.add_expr(&nft_expr!(payload tcp flags));
        ruleset.in_fin.add_expr(&nft_expr!(bitwise mask (TcpFlags::RST | TcpFlags::FIN), xor (0 as u8)));
        ruleset.in_fin.add_expr(&nft_expr!(cmp > (0 as u8)));

        ruleset.in_fin.add_expr(&nft_expr!(
            log .group(TIME_QUOTA_NUM)
                .prefix(&CString::new(format!("{}{}", TIME_FIN_LOG_PREFIX, name.to_owned())).unwrap()) 
            )
        );

        // Output rule for connection end
        ruleset.out_fin.add_expr(&nft_expr!(meta l4proto));
        ruleset.out_fin.add_expr(&nft_expr!(cmp == libc::IPPROTO_TCP as u8));

        ruleset.out_fin.add_expr(&nft_expr!(payload ipv4 daddr));
        ruleset.out_fin.add_expr(&nft_expr!(bitwise mask ip.mask(), xor 0));
        ruleset.out_fin.add_expr(&nft_expr!(cmp == ip.ip()));

        ruleset.out_fin.add_expr(&nft_expr!(payload tcp flags));
        ruleset.out_fin.add_expr(&nft_expr!(bitwise mask (TcpFlags::RST | TcpFlags::FIN), xor (0 as u8)));
        ruleset.out_fin.add_expr(&nft_expr!(cmp > (0 as u8)));

        ruleset.out_fin.add_expr(&nft_expr!(
            log .group(TIME_QUOTA_NUM)
                .prefix(&CString::new(format!("{}{}", TIME_FIN_LOG_PREFIX, name.to_owned())).unwrap()) 
            )
        );

        // Input rule for conn block
        ruleset.block_in.add_expr(&nft_expr!(meta l4proto));
        ruleset.block_in.add_expr(&nft_expr!(cmp == libc::IPPROTO_TCP as u8));

        ruleset.block_in.add_expr(&nft_expr!(payload ipv4 saddr));
        ruleset.block_in.add_expr(&nft_expr!(bitwise mask ip.mask(), xor 0));
        ruleset.block_in.add_expr(&nft_expr!(cmp == ip.ip()));

        ruleset.block_in.add_expr(&nft_expr!(verdict reject));

        // Output rule for conn block
        ruleset.block_out.add_expr(&nft_expr!(meta l4proto));
        ruleset.block_out.add_expr(&nft_expr!(cmp == libc::IPPROTO_TCP as u8));

        ruleset.block_out.add_expr(&nft_expr!(payload ipv4 daddr));
        ruleset.block_out.add_expr(&nft_expr!(bitwise mask ip.mask(), xor 0));
        ruleset.block_out.add_expr(&nft_expr!(cmp == ip.ip()));

        ruleset.block_out.add_expr(&nft_expr!(verdict reject));


        ruleset
    }
}

impl DataLimitRuleset<'_> {
    fn new<'a>(in_chain: &'a Chain, ip: &Ipv4Network, quota_obj: &Quota) -> DataLimitRuleset<'a> {
        let mut ruleset = DataLimitRuleset {
            block: Rule::new(&in_chain),
            log: Rule::new(&in_chain),
        };

        // Input rule for quota accounting and blocking when overflow
        ruleset.block.add_expr(&nft_expr!(payload ipv4 saddr));
        ruleset.block.add_expr(&nft_expr!(bitwise mask ip.mask(), xor 0));
        ruleset.block.add_expr(&nft_expr!(cmp == ip.ip()));
        ruleset.block.add_expr(&nft_expr!(quota quota_obj));
        ruleset.block.add_expr(&nft_expr!(verdict drop));

        let prefix = quota_obj.get_name();
        // Input rule for quota accounting and starting to send logs when overflows
        ruleset.log.add_expr(&nft_expr!(payload ipv4 saddr));
        ruleset.log.add_expr(&nft_expr!(bitwise mask ip.mask(), xor 0));
        ruleset.log.add_expr(&nft_expr!(cmp == ip.ip()));
        ruleset.log.add_expr(&nft_expr!(quota quota_obj));
        ruleset.log.add_expr(&nft_expr!(
            log .group(DATA_QUOTA_NUM)
                .snaplen(0)
                .prefix(&prefix.to_owned()) 
            )
        );

        ruleset
    }
}



// TODO this need some generics ...
#[derive(Debug)]
pub struct NfTimeLimit<'a> {
    timer: ConnTimer<'a>,

    rules: HashMap<Ipv4Network, TimeLimitRuleset<'a>>,
}

#[derive(Debug)]
pub struct NfDataLimit<'a> {
    // Quota object in NF
    quota: Quota<'a>,

    rules: HashMap<Ipv4Network, DataLimitRuleset<'a>>
}

trait NfAction {
    fn add(&self);

    fn delete(&self);

    fn block(&self);

    fn unblock(&self);
}

impl<'a> NfAction for NfTimeLimit<'a> {
    fn add(&self) {
        let mut batch = Batch::new();

        // Adding monitor rules
        for (_, ruleset) in self.rules.iter() {
            batch.add(&ruleset.start, nftnl::MsgType::Add);
            batch.add(&ruleset.in_fin, nftnl::MsgType::Add);
            batch.add(&ruleset.out_fin, nftnl::MsgType::Add);
        }

        process_netlink(&(batch.finalize()), false).unwrap();
        
        unsafe {
            let callback = Box::new(move || self.block());

            self.timer.set_callback(callback);
        }
    }

    fn delete(&self) {
        let mut batch = Batch::new();

        // Clearing monitor and block rules
        for (_, ruleset) in self.rules.iter() {
            batch.add(&ruleset.start, nftnl::MsgType::Del);
            batch.add(&ruleset.in_fin, nftnl::MsgType::Del);
            batch.add(&ruleset.out_fin, nftnl::MsgType::Del);
            batch.add(&ruleset.block_in, nftnl::MsgType::Del);
            batch.add(&ruleset.block_out, nftnl::MsgType::Del);
        }

        process_netlink(&(batch.finalize()), false).unwrap();

        self.timer.clear_callback();
    }

    fn block(&self) {
        let mut batch = Batch::new();

        // Adding block rules
        for (_, ruleset) in self.rules.iter() {
            batch.add(&ruleset.block_in, nftnl::MsgType::Add);
            batch.add(&ruleset.block_out, nftnl::MsgType::Add);
        }

        process_netlink(&(batch.finalize()), false).unwrap();
    }

    fn unblock(&self) {
        let mut batch = Batch::new();

        // Clearing block rules
        for (_, ruleset) in self.rules.iter() {
            batch.add(&ruleset.block_in, nftnl::MsgType::Del);
            batch.add(&ruleset.block_out, nftnl::MsgType::Del);
        }

        process_netlink(&(batch.finalize()), false).unwrap();
    }
}

impl NfAction for NfDataLimit<'_> {
    fn add(&self) {
        let mut batch = Batch::new();

        for (_, ruleset) in self.rules.iter() {
            batch.add(&ruleset.block, nftnl::MsgType::Add);
            batch.add(&ruleset.log, nftnl::MsgType::Add);
        }

        process_netlink(&(batch.finalize()), false).unwrap();
    }

    fn delete(&self) {
        let mut batch = Batch::new();

        for (_, ruleset) in self.rules.iter() {
            batch.add(&ruleset.block, nftnl::MsgType::Del);
            batch.add(&ruleset.log, nftnl::MsgType::Del);
        }

        process_netlink(&(batch.finalize()), false).unwrap();
    }

    // It is already 
    fn block(&self) {
        let mut batch = Batch::new();

        // Just clearing the log rule, for it not post anything to netlink
        for (_, ruleset) in self.rules.iter() {
            batch.add(&ruleset.log, nftnl::MsgType::Del);
        }

        process_netlink(&(batch.finalize()), false).unwrap();
    }

    fn unblock(&self) {
        // TODO reset quota in NF (yet to be implemented)
    }
}

impl NfTimeLimit<'_> {
    pub fn new<'a>(
        acc_entry: &Accounting<Duration>,
        in_chain: &'a Chain,
        out_chain: &'a Chain,
        name: &'a str) -> NfTimeLimit<'a> {
        let dur = acc_entry.quota.clone();
        let mut limit = NfTimeLimit {
            timer: ConnTimer::new(&dur),
            rules: HashMap::new(),
        };

        for ip in acc_entry.addr.value.iter() {
            let ruleset = TimeLimitRuleset::new(out_chain, in_chain, ip, name);

            limit.rules.insert(ip.clone(), ruleset);
        }

        limit
    }
}

impl NfDataLimit<'_> {
    pub fn new<'a>(
        acc_entry: &Accounting<Byte>,
        in_chain: &'a Chain,
        name: &'a str) -> NfDataLimit<'a> {
        let mut quota = Quota::new(&CString::new(name).unwrap(), in_chain.get_table());
        quota.set_type(QuotaType::Over);
        quota.set_limit(acc_entry.quota.to_quota() as u64);

        let mut limit = NfDataLimit {
            quota,
            rules: HashMap::new(),
        };

        for ip in acc_entry.addr.value.iter() {
            let ruleset = DataLimitRuleset::new(in_chain, ip, &limit.quota);

            limit.rules.insert(*ip, ruleset);
        }

        limit
    }
}

static mut HANDLE_INSTANCE: OnceCell<NfHandle> = OnceCell::new();

#[derive(Debug)]
pub enum NfError {
    // File not found or whateva ...
    NfLogError(nflog::NflogError),
    // Parse line error
    NfTablesError(String),
    // Other error
    UnknownError,
}

impl From<io::Error> for NfError {
    fn from(e: io::Error) -> Self {
        NfError::NfTablesError(e.to_string())
    }
}

impl From<nflog::NflogError> for NfError {
    fn from(e: nflog::NflogError) -> Self {
        NfError::NfLogError(e)
    }
}

fn data_quota_cb(msg: nflog::Message) {
    debug!("data_quota_cb -> prefix: {}", msg.get_prefix().to_string_lossy());

    // println!("Packet received\n");
    // println!(
    //     " -> uid: {}, gid: {}",
    //     msg.get_uid().unwrap_or(0xffff),
    //     msg.get_gid().unwrap_or(0xffff)
    // );
    
    // println!(" -> seq: {}", msg.get_seq().unwrap_or(0xffff));

    // let payload_data = msg.get_payload();
    // let mut s = String::new();
    // for &byte in payload_data {
    //     write!(&mut s, "{:02X} ", byte).unwrap();
    // }
    // println!("{}", s);

    // let hwaddr = msg.get_packet_hw().unwrap_or_default();
    // println!("{}", hwaddr);
}

// This one will call the the "subcallbacks" for time count
fn time_quota_cb(msg: nflog::Message) {
    debug!("time_quota_cb -> prefix: {}", msg.get_prefix().to_string_lossy());
}

pub fn init<'a>(config: &Config) -> Result<(), NfError> {
    let mut handle = NfHandle::new(TABLE_NAME);
    unsafe { HANDLE_INSTANCE.set(handle).unwrap(); }

    let mut init_batch = Batch::new();

    init_batch.add(&NfHandle::get().table, nftnl::MsgType::Add);

    let (mut dataqt_in_chain, mut dataqt_out_chain, mut timeqt_in_chain, mut timeqt_out_chain) = 
        (
            Chain::new(&CString::new(DATA_IN_CHAIN_NAME).unwrap(), &NfHandle::get().table),
            Chain::new(&CString::new(DATA_OUT_CHAIN_NAME).unwrap(), &NfHandle::get().table),
            Chain::new(&CString::new(TIME_IN_CHAIN_NAME).unwrap(), &NfHandle::get().table),
            Chain::new(&CString::new(TIME_OUT_CHAIN_NAME).unwrap(), &NfHandle::get().table)
        );
    
    dataqt_in_chain.set_hook(nftnl::Hook::In, 0);
    dataqt_in_chain.set_policy(nftnl::Policy::Accept);
    dataqt_in_chain.set_type(ChainType::Filter);
    
    dataqt_out_chain.set_hook(nftnl::Hook::Out, 0);
    dataqt_out_chain.set_policy(nftnl::Policy::Accept);
    dataqt_out_chain.set_type(ChainType::Filter);
    
    timeqt_in_chain.set_hook(nftnl::Hook::In, 0);
    timeqt_in_chain.set_policy(nftnl::Policy::Accept);
    timeqt_in_chain.set_type(ChainType::Filter);
    
    timeqt_out_chain.set_hook(nftnl::Hook::Out, 0);
    timeqt_out_chain.set_policy(nftnl::Policy::Accept);
    timeqt_out_chain.set_type(ChainType::Filter);

    init_batch.add(&dataqt_in_chain, nftnl::MsgType::Add);
    init_batch.add(&dataqt_out_chain, nftnl::MsgType::Add);
    init_batch.add(&timeqt_in_chain, nftnl::MsgType::Add);
    init_batch.add(&timeqt_out_chain, nftnl::MsgType::Add);

    NfHandle::get().chains.insert(DATA_IN_CHAIN_NAME, dataqt_in_chain);
    NfHandle::get().chains.insert(DATA_OUT_CHAIN_NAME, dataqt_out_chain);
    NfHandle::get().chains.insert(TIME_IN_CHAIN_NAME, timeqt_in_chain);
    NfHandle::get().chains.insert(TIME_OUT_CHAIN_NAME, timeqt_out_chain);

    // Process messages with little portions, not to overflow nl sokcet
    process_netlink(&(init_batch.finalize()), false).unwrap();

    // Process data quota entries
    for (pos, data_entry) in config.data.iter().enumerate() {

        let name = format!("{}{}", DATA_LOG_PREFIX, pos.to_string());

        let limit = NfDataLimit::new(
            data_entry,
            NfHandle::get().chains.get(DATA_IN_CHAIN_NAME).unwrap(),
            &name
        );

        limit.add();

        NfHandle::get().data_entries.insert(&name, limit);
    }

    // Process time quota entries
    for (pos, time_entry) in config.time.iter().enumerate() {
        let name = format!("{}{}", TIME_LOG_PREFIX, pos.to_string());

        let limit = NfTimeLimit::new(
            time_entry,
            NfHandle::get().chains.get(TIME_IN_CHAIN_NAME).unwrap(),
            NfHandle::get().chains.get(TIME_OUT_CHAIN_NAME).unwrap(),
            &name
        );

        limit.add();

        NfHandle::get().time_entries.insert(&name, limit);
    }


    // Setting nflog
    let (mut data_quota_group, mut time_quota_group) = 
        (
            NfHandle::get().log.queue.bind_group(DATA_QUOTA_NUM).unwrap(),
            NfHandle::get().log.queue.bind_group(TIME_QUOTA_NUM).unwrap(),
        );

    data_quota_group.set_mode(nflog::CopyMode::Meta, 0xffff);
    time_quota_group.set_mode(nflog::CopyMode::Meta, 0xffff);

    data_quota_group.set_flags(nflog::Flags::Sequence);
    time_quota_group.set_flags(nflog::Flags::Sequence);

    data_quota_group.set_callback(Box::new(data_quota_cb));
    time_quota_group.set_callback(Box::new(time_quota_cb));

    NfHandle::get().log.groups.push(data_quota_group);
    NfHandle::get().log.groups.push(time_quota_group);

    Ok(())
}

pub fn deinit() -> Result<(), NfError> {
    // TODO check if initialised
    let mut batch = Batch::new();

    // Dropping table with all the chains, quotas and rules with it
    batch.add(&NfHandle::get().table, nftnl::MsgType::Del);
    process_netlink(&(batch.finalize()), true)?;
    Ok(())
}

pub fn run() {
    // TODO check if initialised
    NfHandle::get().log.queue.run_loop();
}

fn process_netlink(batch: &FinalizedBatch, ack_wait: bool) -> Result<(), NfError> {
    let socket = mnl::Socket::new(mnl::Bus::Netfilter)?;
    socket.send_all(batch)?;

    // TODO investigate: time quota rules hangs on "recvmsg(int, struct msghdr *, int)" call
    if ack_wait {
        let mut buffer = vec![0; nftnl::nft_nlmsg_maxsize() as usize];

        while let Some(message) = socket_recv(&socket, &mut buffer[..])? {
            match mnl::cb_run(message, 2, socket.portid())? {
                mnl::CbResult::Stop => {
                    break;
                }
                mnl::CbResult::Ok => (),
            }
        }
    }

    Ok(())
}

fn socket_recv<'a>(socket: &mnl::Socket, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, NfError> {
    
    // FD_ZERO(&readfds);
    // FD_SET(fd, &readfds);

    // ret = select(fd + 1, &readfds, NULL, NULL, &tv);
    // if (ret == -1)
    //     return -1;

    // if (!FD_ISSET(fd, &readfds))
    //     break;

    // ret = mnl_socket_recvfrom(nl, rcv_buf, sizeof(rcv_buf));
    // if (ret == -1)
    //     return -1;

    // /* Continue on error, make sure we get all acknowledgments */
    // ret = mnl_cb_run2(rcv_buf, ret, 0, portid,
    //           netlink_echo_callback, &cb_data,
    //           cb_ctl_array, MNL_ARRAY_SIZE(cb_ctl_array));

    // TODO implement this code ^^^

    let ret = socket.recv(buf)?;
    if ret > 0 {
        Ok(Some(&buf[..ret]))
    } else {
        Ok(None)
    }
}

