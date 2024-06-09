use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::Arc;

#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct Interruptor(Arc<AtomicBool>);

impl Interruptor {
    pub fn new() -> Self {
        Interruptor(Arc::new(AtomicBool::new(false)))
    }

    pub fn set(&self) {
        self.0.store(true, SeqCst);
    }

    pub fn is_set(&self) -> bool {
        self.0.load(SeqCst)
    }
}

impl Default for Interruptor {
    fn default() -> Self {
        Self::new()
    }
}
