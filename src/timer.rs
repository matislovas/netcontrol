
use timer;
use chrono;
use std::{
    fmt,
    sync::Arc,
    sync::Mutex,
    time::Duration,
};


type Callback<'a> = Box<dyn Fn() + Sync + 'a>;

pub struct ConnTimer<'a> {
    timer: Option<timer::Timer>,
    guard: Option<timer::Guard>,
    target_secs: u64,
    current_secs: Arc<Mutex<u64>>,
    active: bool,
    cb: Option<Box<Callback<'a>>>,
}

impl fmt::Debug for ConnTimer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {        
        f.debug_struct("ConnTimer")
            .field("target", &self.target_secs)
            .field("current", &self.current_secs)
            .field("active", &self.active)
            .field("has_callback", &self.cb.is_some())
            .finish()
    }
}

// unsafe impl Send for ConnTimer<'_> {}
unsafe impl Sync for ConnTimer<'_> {}

impl<'a> ConnTimer<'a> {
    pub fn new(target: &Duration) -> ConnTimer {
        let dur_cp = target.clone();
        
        ConnTimer {
            timer: None,
            guard: None,
            target_secs: dur_cp.as_secs() as u64,
            current_secs: Arc::new(Mutex::new(0 as u64)),
            active: false,
            cb: None,
        }
    }

    pub fn set_callback(&self, cb: Callback<'a>) {
        let cb_box = Box::new(cb);
        self.cb = Some(cb_box);
    }

    pub fn clear_callback(&self) {
        self.cb = None;
    }

    pub fn start(&self) {
        let timer = timer::Timer::new();
        let guard = {
            let count = self.current_secs.clone();

            timer.schedule_repeating(chrono::Duration::seconds(1), move || {
                *count.lock().unwrap() += 1;

                if *count.lock().unwrap() >= self.target_secs {
                    match self.cb {
                        Some(cb) => {
                            // unsafe {
                            //     cb();
                            // }
                        },
                        None => (),
                    }

                    self.stop();
                }
            })
        };

        self.guard = Some(guard);
        self.timer = Some(timer);
        self.active = true;
    }

    pub fn stop(&self) {
        self.guard = None;
        self.timer = None;
        self.active = false;
    }

    pub fn reset(&self) {
        let count = self.current_secs.clone();
        *count.lock().unwrap() = 0;
    }
}
