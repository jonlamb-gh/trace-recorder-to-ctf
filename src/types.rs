use babeltrace2_sys::{ffi, Error, MessageIteratorStatus, SelfMessageIterator};
use std::collections::{hash_map, HashMap};
use std::ffi::{CStr, CString};
use trace_recorder_parser::{
    streaming::event::{EventType, IsrEvent, TaskEvent},
    time::Timestamp,
    types::{ObjectHandle, ObjectName, Priority},
};

#[derive(Debug)]
pub struct Context {
    pub handle: ObjectHandle,
    pub name: ObjectName,
    pub priority: Priority,
}

impl From<TaskEvent> for Context {
    fn from(value: TaskEvent) -> Self {
        Self {
            handle: value.handle,
            name: value.name,
            priority: value.priority,
        }
    }
}

impl From<IsrEvent> for Context {
    fn from(value: IsrEvent) -> Self {
        Self {
            handle: value.handle,
            name: value.name,
            priority: value.priority,
        }
    }
}

#[derive(Default)]
pub struct StringCache {
    strings: HashMap<String, CString>,
    event_types: HashMap<EventType, CString>,
}

impl StringCache {
    pub fn insert_str(&mut self, key: &str) -> Result<(), Error> {
        if !self.strings.contains_key(key) {
            self.strings.insert(key.to_string(), CString::new(key)?);
        }
        Ok(())
    }

    pub fn get_str(&self, key: &str) -> &CStr {
        self.strings
            .get(key)
            .expect("String cache string entry doesn't exist")
    }

    pub fn insert_type(&mut self, key: EventType) -> Result<(), Error> {
        if let hash_map::Entry::Vacant(e) = self.event_types.entry(key) {
            e.insert(CString::new(key.to_string())?);
        }
        Ok(())
    }

    pub fn get_type(&self, key: &EventType) -> &CStr {
        self.event_types
            .get(key)
            .expect("String cache event type entry doesn't exist")
    }
}

// TODO split up the roles of this, currently just a catch all
pub struct BorrowedCtfState<'a> {
    stream: *mut ffi::bt_stream,
    packet: *mut ffi::bt_packet,
    msg_iter: SelfMessageIterator,
    messages: &'a mut [*const ffi::bt_message],
    msgs_len: usize,
}

impl<'a> BorrowedCtfState<'a> {
    pub fn new(
        stream: *mut ffi::bt_stream,
        packet: *mut ffi::bt_packet,
        msg_iter: SelfMessageIterator,
        messages: &'a mut [*const ffi::bt_message],
    ) -> Self {
        assert!(!stream.is_null());
        assert!(!packet.is_null());
        assert!(!messages.is_empty());
        Self {
            stream,
            packet,
            msg_iter,
            messages,
            msgs_len: 0,
        }
    }

    pub fn release(self) -> MessageIteratorStatus {
        if self.msgs_len == 0 {
            MessageIteratorStatus::NoMessages
        } else {
            MessageIteratorStatus::Messages(self.msgs_len as u64)
        }
    }

    pub fn stream_mut(&mut self) -> *mut ffi::bt_stream {
        self.stream
    }

    pub fn message_iter_mut(&mut self) -> *mut ffi::bt_self_message_iterator {
        self.msg_iter.inner_mut()
    }

    pub fn create_message(
        &mut self,
        event_class: *const ffi::bt_event_class,
        timestamp: Timestamp,
    ) -> *mut ffi::bt_message {
        unsafe {
            ffi::bt_message_event_create_with_packet_and_default_clock_snapshot(
                self.msg_iter.inner_mut(),
                event_class,
                self.packet,
                timestamp.ticks(),
            )
        }
    }

    pub fn push_message(&mut self, msg: *const ffi::bt_message) -> Result<(), Error> {
        if msg.is_null() {
            Err(Error::PluginError("MessageVec: msg is NULL".to_owned()))
        } else if self.msgs_len >= self.messages.len() {
            Err(Error::PluginError("MessageVec: full".to_owned()))
        } else {
            self.messages[self.msgs_len] = msg;
            self.msgs_len += 1;
            Ok(())
        }
    }
}
