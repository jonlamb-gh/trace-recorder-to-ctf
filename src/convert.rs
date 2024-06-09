use crate::types::BorrowedCtfState;
use babeltrace2_sys::{ffi, BtResultExt, Error};
use std::collections::{hash_map::Entry, HashMap};
use std::{ffi::CString, ptr};
use trace_recorder_parser::{streaming::event::*, time::Timestamp, types::*};
use tracing::warn;

pub struct TrcCtfConverter {
    event_type_strings: HashMap<EventType, CString>,
    unknown_event_class: *mut ffi::bt_event_class,
    user_event_class: *mut ffi::bt_event_class,
    sched_switch_event_class: *mut ffi::bt_event_class,
    irq_handler_entry_event_class: *mut ffi::bt_event_class,
    irq_handler_exit_event_class: *mut ffi::bt_event_class,
    sched_wakeup_event_class: *mut ffi::bt_event_class,
    event_classes: HashMap<EventType, *mut ffi::bt_event_class>,
    string_cache: StringCache,
    active_context: Context,
    pending_isrs: Vec<Context>,
}

impl Drop for TrcCtfConverter {
    fn drop(&mut self) {
        unsafe {
            for (_, event_class) in self.event_classes.drain() {
                ffi::bt_event_class_put_ref(event_class);
            }
            ffi::bt_event_class_put_ref(self.sched_wakeup_event_class);
            ffi::bt_event_class_put_ref(self.irq_handler_entry_event_class);
            ffi::bt_event_class_put_ref(self.irq_handler_exit_event_class);
            ffi::bt_event_class_put_ref(self.sched_switch_event_class);
            ffi::bt_event_class_put_ref(self.user_event_class);
            ffi::bt_event_class_put_ref(self.unknown_event_class);
        }
    }
}

impl TrcCtfConverter {
    pub fn new() -> Self {
        Self {
            event_type_strings: Default::default(),
            unknown_event_class: ptr::null_mut(),
            user_event_class: ptr::null_mut(),
            sched_switch_event_class: ptr::null_mut(),
            irq_handler_entry_event_class: ptr::null_mut(),
            irq_handler_exit_event_class: ptr::null_mut(),
            sched_wakeup_event_class: ptr::null_mut(),
            event_classes: Default::default(),
            string_cache: Default::default(),
            active_context: Context {
                handle: ObjectHandle::NO_TASK,
                name: STARTUP_TASK_NAME.to_string().into(),
                priority: 0_u32.into(),
            },
            pending_isrs: Default::default(),
        }
    }

    pub fn create_event_common_context(
        &mut self,
        trace_class: *mut ffi::bt_trace_class,
    ) -> Result<*mut ffi::bt_field_class, Error> {
        unsafe {
            // Create common event context
            // event ID, event type, event count, timer ticks
            let base_event_context = ffi::bt_field_class_structure_create(trace_class);

            let event_id_field = ffi::bt_field_class_integer_unsigned_create(trace_class);
            ffi::bt_field_class_integer_set_preferred_display_base(
            event_id_field,
            ffi::bt_field_class_integer_preferred_display_base::BT_FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_HEXADECIMAL,
        );
            let ret = ffi::bt_field_class_structure_append_member(
                base_event_context,
                b"id\0".as_ptr() as _,
                event_id_field,
            );
            ret.capi_result()?;

            let event_count_field = ffi::bt_field_class_integer_unsigned_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                base_event_context,
                b"event_count\0".as_ptr() as _,
                event_count_field,
            );
            ret.capi_result()?;

            let timer_field = ffi::bt_field_class_integer_unsigned_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                base_event_context,
                b"timer\0".as_ptr() as _,
                timer_field,
            );
            ret.capi_result()?;

            ffi::bt_field_class_put_ref(timer_field);
            ffi::bt_field_class_put_ref(event_count_field);
            ffi::bt_field_class_put_ref(event_id_field);

            Ok(base_event_context)
        }
    }

    /// Create the special event classes upfront, remaining classes will get
    /// created on the fly
    pub fn create_event_classes(&mut self, stream: *mut ffi::bt_stream) -> Result<(), Error> {
        let stream_class = unsafe { ffi::bt_stream_borrow_class(stream) };
        self.unknown_event_class = unknown::event_class(stream_class)?;
        self.user_event_class = user::event_class(stream_class)?;
        self.sched_switch_event_class = sched_switch::event_class(stream_class)?;
        self.irq_handler_entry_event_class = irq_handler_entry::event_class(stream_class)?;
        self.irq_handler_exit_event_class = irq_handler_exit::event_class(stream_class)?;
        self.sched_wakeup_event_class = sched_wakeup::event_class(stream_class)?;
        Ok(())
    }

    fn event_type_str(&mut self, event_type: EventType) -> Result<&CString, Error> {
        Ok(match self.event_type_strings.entry(event_type) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => {
                let s = CString::new(event_type.to_string())?;
                v.insert(s)
            }
        })
    }

    fn add_event_common_ctx(
        &mut self,
        event_id: EventId,
        event_count: u64,
        timer: Timestamp,
        event: *mut ffi::bt_event,
    ) -> Result<(), Error> {
        unsafe {
            let common_ctx_field = ffi::bt_event_borrow_common_context_field(event);

            let event_id_field =
                ffi::bt_field_structure_borrow_member_field_by_index(common_ctx_field, 0);
            ffi::bt_field_integer_unsigned_set_value(event_id_field, event_id.0 as u64);

            let event_count_field =
                ffi::bt_field_structure_borrow_member_field_by_index(common_ctx_field, 1);
            ffi::bt_field_integer_unsigned_set_value(event_count_field, event_count);

            let timer_field =
                ffi::bt_field_structure_borrow_member_field_by_index(common_ctx_field, 2);
            ffi::bt_field_integer_unsigned_set_value(timer_field, timer.ticks());

            Ok(())
        }
    }

    fn event_class<F>(
        &mut self,
        stream_class: *mut ffi::bt_stream_class,
        event_type: EventType,
        f: F,
    ) -> Result<*const ffi::bt_event_class, Error>
    where
        F: FnOnce(*mut ffi::bt_stream_class) -> Result<*mut ffi::bt_event_class, Error>,
    {
        let event_class_ref = match self.event_classes.entry(event_type) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => {
                let event_class = f(stream_class)?;
                v.insert(event_class)
            }
        };
        Ok(*event_class_ref as *const _)
    }

    pub fn convert(
        &mut self,
        event_code: EventCode,
        tracked_event_count: u64,
        tracked_timestamp: Timestamp,
        event: &Event,
        ctf_state: &mut BorrowedCtfState,
    ) -> Result<(), Error> {
        let event_id = event_code.event_id();
        let event_type = event_code.event_type();
        let raw_timestamp = event.timestamp();

        let stream_class = unsafe { ffi::bt_stream_borrow_class(ctf_state.stream_mut()) };

        match event {
            Event::TraceStart(ev) => {
                let event_class =
                    self.event_class(stream_class, event_type, trace_start::event_class)?;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                self.active_context.handle = ev.current_task_handle;
                self.active_context.name = ev.current_task.clone();
                trace_start::event(ev, &mut self.string_cache, ctf_event)?;
                ctf_state.push_message(msg)?;
            }

            Event::TaskReady(ev) => {
                let type_str = self.event_type_str(event_type)?.as_ptr();
                let event_class = self.sched_wakeup_event_class;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                sched_wakeup::event(ev, type_str, &mut self.string_cache, ctf_event)?;
                ctf_state.push_message(msg)?;
            }

            Event::TaskResume(ev) | Event::TaskActivate(ev) => {
                // Check for return from ISR
                if let Some(isr) = self.pending_isrs.pop() {
                    // TODO should sched_switch be created if on the same context?
                    // depends on the arg given to xTraceISREnd(arg)
                    let type_str = self.event_type_str(event_type)?.as_ptr();
                    let event_class = self.irq_handler_exit_event_class;
                    let msg = ctf_state.create_message(event_class, tracked_timestamp);
                    let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                    self.add_event_common_ctx(
                        event_id,
                        tracked_event_count,
                        raw_timestamp,
                        ctf_event,
                    )?;
                    irq_handler_exit::event(isr.handle, type_str, ctf_event)?;
                    ctf_state.push_message(msg)?;
                }

                let next_context = Context {
                    handle: ev.handle,
                    name: ev.name.clone(),
                    priority: ev.priority,
                };
                let type_str = self.event_type_str(event_type)?.as_ptr();
                let event_class = self.sched_switch_event_class;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                sched_switch::event(
                    &self.active_context,
                    &next_context,
                    type_str,
                    &mut self.string_cache,
                    ctf_event,
                )?;
                self.active_context = next_context;
                ctf_state.push_message(msg)?;
            }

            Event::IsrBegin(ev) => {
                let context = Context {
                    handle: ev.handle,
                    name: ev.name.clone(),
                    priority: ev.priority,
                };
                self.pending_isrs.push(context);
                let type_str = self.event_type_str(event_type)?.as_ptr();
                let event_class = self.irq_handler_entry_event_class;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                irq_handler_entry::event(ev, type_str, &mut self.string_cache, ctf_event)?;
                ctf_state.push_message(msg)?;
            }

            // Return to the interrupted ISR (nested ISR)
            Event::IsrResume(ev) if !self.pending_isrs.is_empty() => {
                let isr = self.pending_isrs.pop().unwrap();
                assert_eq!(ev.handle, isr.handle);
                let type_str = self.event_type_str(event_type)?.as_ptr();
                let event_class = self.irq_handler_exit_event_class;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                irq_handler_exit::event(isr.handle, type_str, ctf_event)?;
                ctf_state.push_message(msg)?;
            }

            Event::Unknown(_) => {
                let type_str = self.event_type_str(event_type)?.as_ptr();
                let event_class = self.unknown_event_class;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                unknown::event(type_str, ctf_event)?;
                ctf_state.push_message(msg)?;
            }

            Event::User(ev) => {
                let event_class = self.user_event_class;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                user::event(ev, &mut self.string_cache, ctf_event)?;
                ctf_state.push_message(msg)?;
            }

            // The rest are named events with no payload
            _ => {
                if let Event::IsrResume(ev) = event {
                    warn!(%event_type, event = %ev, "Got ISR resume but no pending IRS");
                }

                let type_str = self.event_type_str(event_type)?.as_ptr();
                let event_class =
                    self.event_class(stream_class, event_type, |stream_class| unsafe {
                        let event_class = ffi::bt_event_class_create(stream_class);
                        let ret = ffi::bt_event_class_set_name(event_class, type_str);
                        ret.capi_result()?;
                        Ok(event_class)
                    })?;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                ctf_state.push_message(msg)?;
            }
        }

        Ok(())
    }
}

#[derive(Default)]
struct StringCache(HashMap<String, CString>);

impl StringCache {
    fn get_or_insert(&mut self, key: &str) -> Result<&CString, Error> {
        // TODO don't clone
        Ok(match self.0.entry(key.to_string()) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => {
                let s = CString::new(key)?;
                v.insert(s)
            }
        })
    }
}

struct Context {
    handle: ObjectHandle,
    name: ObjectName,
    priority: Priority,
}

// TODO - write a proc macro to derive these impls

mod unknown {
    use super::*;

    pub fn event_class(
        stream_class: *mut ffi::bt_stream_class,
    ) -> Result<*mut ffi::bt_event_class, Error> {
        unsafe {
            let trace_class = ffi::bt_stream_class_borrow_trace_class(stream_class);

            let event_class = ffi::bt_event_class_create(stream_class);
            let ret = ffi::bt_event_class_set_name(event_class, b"UNKNOWN\0".as_ptr() as _);
            ret.capi_result()?;

            let payload_fc = ffi::bt_field_class_structure_create(trace_class);

            let event_type_fc = ffi::bt_field_class_string_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"type\0".as_ptr() as _,
                event_type_fc,
            );
            ret.capi_result()?;

            let ret = ffi::bt_event_class_set_payload_field_class(event_class, payload_fc);
            ret.capi_result()?;

            ffi::bt_field_class_put_ref(event_type_fc);
            ffi::bt_field_class_put_ref(payload_fc);

            Ok(event_class)
        }
    }

    pub fn event(event_type_str: *const i8, ctf_event: *mut ffi::bt_event) -> Result<(), Error> {
        unsafe {
            let payload_f = ffi::bt_event_borrow_payload_field(ctf_event);

            let event_type_f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 0);
            let ret = ffi::bt_field_string_set_value(event_type_f, event_type_str);
            ret.capi_result()?;

            Ok(())
        }
    }
}

mod trace_start {
    use super::*;

    pub fn event_class(
        stream_class: *mut ffi::bt_stream_class,
    ) -> Result<*mut ffi::bt_event_class, Error> {
        unsafe {
            let trace_class = ffi::bt_stream_class_borrow_trace_class(stream_class);

            let event_class = ffi::bt_event_class_create(stream_class);
            let ret = ffi::bt_event_class_set_name(event_class, b"TRACE_START\0".as_ptr() as _);
            ret.capi_result()?;

            let payload_fc = ffi::bt_field_class_structure_create(trace_class);

            let task_handle_fc = ffi::bt_field_class_integer_unsigned_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"task_handle\0".as_ptr() as _,
                task_handle_fc,
            );
            ret.capi_result()?;

            let task_fc = ffi::bt_field_class_string_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"task\0".as_ptr() as _,
                task_fc,
            );
            ret.capi_result()?;

            let ret = ffi::bt_event_class_set_payload_field_class(event_class, payload_fc);
            ret.capi_result()?;

            ffi::bt_field_class_put_ref(task_handle_fc);
            ffi::bt_field_class_put_ref(payload_fc);

            Ok(event_class)
        }
    }

    pub fn event(
        event: &TraceStartEvent,
        string_cache: &mut StringCache,
        ctf_event: *mut ffi::bt_event,
    ) -> Result<(), Error> {
        unsafe {
            let payload_f = ffi::bt_event_borrow_payload_field(ctf_event);

            let task_handle_f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 0);
            ffi::bt_field_integer_unsigned_set_value(
                task_handle_f,
                u32::from(event.current_task_handle).into(),
            );

            let task_f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 1);
            let n = string_cache.get_or_insert(&event.current_task)?;
            let ret = ffi::bt_field_string_set_value(task_f, n.as_c_str().as_ptr() as _);
            ret.capi_result()?;

            Ok(())
        }
    }
}

mod user {
    use super::*;

    pub fn event_class(
        stream_class: *mut ffi::bt_stream_class,
    ) -> Result<*mut ffi::bt_event_class, Error> {
        unsafe {
            let trace_class = ffi::bt_stream_class_borrow_trace_class(stream_class);

            let event_class = ffi::bt_event_class_create(stream_class);
            let ret = ffi::bt_event_class_set_name(event_class, b"USER_EVENT\0".as_ptr() as _);
            ret.capi_result()?;

            let payload_fc = ffi::bt_field_class_structure_create(trace_class);

            let channel_fc = ffi::bt_field_class_string_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"channel\0".as_ptr() as _,
                channel_fc,
            );
            ret.capi_result()?;

            let formatted_string_fc = ffi::bt_field_class_string_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"formatted_string\0".as_ptr() as _,
                formatted_string_fc,
            );
            ret.capi_result()?;

            let ret = ffi::bt_event_class_set_payload_field_class(event_class, payload_fc);
            ret.capi_result()?;

            ffi::bt_field_class_put_ref(formatted_string_fc);
            ffi::bt_field_class_put_ref(channel_fc);
            ffi::bt_field_class_put_ref(payload_fc);

            Ok(event_class)
        }
    }

    pub fn event(
        event: &UserEvent,
        string_cache: &mut StringCache,
        ctf_event: *mut ffi::bt_event,
    ) -> Result<(), Error> {
        unsafe {
            let payload_f = ffi::bt_event_borrow_payload_field(ctf_event);

            let channel_f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 0);
            let ch = match &event.channel {
                UserEventChannel::Default => UserEventChannel::DEFAULT,
                UserEventChannel::Custom(c) => c.as_str(),
            };
            let n = string_cache.get_or_insert(ch)?;
            let ret = ffi::bt_field_string_set_value(channel_f, n.as_c_str().as_ptr() as _);
            ret.capi_result()?;

            let fmt_str_f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 1);
            let n = string_cache.get_or_insert(&event.formatted_string)?;
            let ret = ffi::bt_field_string_set_value(fmt_str_f, n.as_c_str().as_ptr() as _);
            ret.capi_result()?;

            Ok(())
        }
    }
}

mod sched_switch {
    use super::*;
    use enum_iterator::Sequence;

    #[repr(i64)]
    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Sequence)]
    pub enum TaskState {
        Running = 0,
        Interruptible = 1,
        UnInterruptible = 2,
        Stopped = 4,
        Traced = 8,
        ExitDead = 16,
        ExitZombie = 32,
        Parked = 64,
        Dead = 128,
        WakeKill = 256,
        Waking = 512,
        NoLoad = 1024,
        New = 2048,
    }

    impl TaskState {
        fn as_ffi(&self) -> *const i8 {
            let ptr = match self {
                TaskState::Running => b"TASK_RUNNING\0".as_ptr(),
                TaskState::Interruptible => b"TASK_INTERRUPTIBLE\0".as_ptr(),
                TaskState::UnInterruptible => b"TASK_UNINTERRUPTIBLE\0".as_ptr(),
                TaskState::Stopped => b"TASK_STOPPED\0".as_ptr(),
                TaskState::Traced => b"TASK_TRACED\0".as_ptr(),
                TaskState::ExitDead => b"EXIT_DEAD\0".as_ptr(),
                TaskState::ExitZombie => b"EXIT_ZOMBIE\0".as_ptr(),
                TaskState::Parked => b"TASK_PARKED\0".as_ptr(),
                TaskState::Dead => b"TASK_DEAD\0".as_ptr(),
                TaskState::WakeKill => b"TASK_WAKEKILL\0".as_ptr(),
                TaskState::Waking => b"TASK_WAKING\0".as_ptr(),
                TaskState::NoLoad => b"TASK_NOLOAD\0".as_ptr(),
                TaskState::New => b"TASK_NEW\0".as_ptr(),
            };
            ptr as *const i8
        }

        fn as_i64(&self) -> i64 {
            *self as i64
        }
    }

    pub fn event_class(
        stream_class: *mut ffi::bt_stream_class,
    ) -> Result<*mut ffi::bt_event_class, Error> {
        unsafe {
            let trace_class = ffi::bt_stream_class_borrow_trace_class(stream_class);

            let event_class = ffi::bt_event_class_create(stream_class);
            let ret = ffi::bt_event_class_set_name(event_class, b"sched_switch\0".as_ptr() as _);
            ret.capi_result()?;

            let payload_fc = ffi::bt_field_class_structure_create(trace_class);

            let fc = ffi::bt_field_class_string_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"src_event_type\0".as_ptr() as _,
                fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(fc);

            let prev_comm_fc = ffi::bt_field_class_string_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"prev_comm\0".as_ptr() as _,
                prev_comm_fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(prev_comm_fc);

            let prev_tid_fc = ffi::bt_field_class_integer_signed_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"prev_tid\0".as_ptr() as _,
                prev_tid_fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(prev_tid_fc);

            let prev_prio_fc = ffi::bt_field_class_integer_signed_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"prev_prio\0".as_ptr() as _,
                prev_prio_fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(prev_prio_fc);

            let prev_state_fc = ffi::bt_field_class_enumeration_signed_create(trace_class);
            let states = enum_iterator::all::<TaskState>().collect::<Vec<_>>();
            for state in states.into_iter() {
                let state_rs = ffi::bt_integer_range_set_signed_create();
                let ret = ffi::bt_integer_range_set_signed_add_range(
                    state_rs,
                    state.as_i64(),
                    state.as_i64(),
                );
                ret.capi_result()?;
                let ret = ffi::bt_field_class_enumeration_signed_add_mapping(
                    prev_state_fc,
                    state.as_ffi(),
                    state_rs,
                );
                ret.capi_result()?;
                ffi::bt_integer_range_set_signed_put_ref(state_rs);
            }
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"prev_state\0".as_ptr() as _,
                prev_state_fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(prev_state_fc);

            let next_comm_fc = ffi::bt_field_class_string_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"next_comm\0".as_ptr() as _,
                next_comm_fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(next_comm_fc);

            let next_tid_fc = ffi::bt_field_class_integer_signed_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"next_tid\0".as_ptr() as _,
                next_tid_fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(next_tid_fc);

            let next_prio_fc = ffi::bt_field_class_integer_signed_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"next_prio\0".as_ptr() as _,
                next_prio_fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(next_prio_fc);

            let ret = ffi::bt_event_class_set_payload_field_class(event_class, payload_fc);
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(payload_fc);

            Ok(event_class)
        }
    }

    // TODO prev state is hard coded to TASK_RUNNING
    pub fn event(
        prev_context: &Context,
        next_context: &Context,
        src_event_type_str: *const i8, // TODO
        string_cache: &mut StringCache,
        ctf_event: *mut ffi::bt_event,
    ) -> Result<(), Error> {
        unsafe {
            let payload_f = ffi::bt_event_borrow_payload_field(ctf_event);

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 0);
            let ret = ffi::bt_field_string_set_value(f, src_event_type_str);
            ret.capi_result()?;

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 1);
            let n = string_cache.get_or_insert(&prev_context.name)?;
            let ret = ffi::bt_field_string_set_value(f, n.as_c_str().as_ptr() as _);
            ret.capi_result()?;

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 2);
            ffi::bt_field_integer_signed_set_value(f, u32::from(prev_context.handle).into());

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 3);
            ffi::bt_field_integer_signed_set_value(f, u32::from(prev_context.priority).into());

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 4);
            ffi::bt_field_integer_signed_set_value(f, TaskState::Running.as_i64());

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 5);
            let n = string_cache.get_or_insert(&next_context.name)?;
            let ret = ffi::bt_field_string_set_value(f, n.as_c_str().as_ptr() as _);
            ret.capi_result()?;

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 6);
            ffi::bt_field_integer_signed_set_value(f, u32::from(next_context.handle).into());

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 7);
            ffi::bt_field_integer_signed_set_value(f, u32::from(next_context.priority).into());

            Ok(())
        }
    }
}

mod irq_handler_entry {
    use super::*;

    pub fn event_class(
        stream_class: *mut ffi::bt_stream_class,
    ) -> Result<*mut ffi::bt_event_class, Error> {
        unsafe {
            let trace_class = ffi::bt_stream_class_borrow_trace_class(stream_class);

            let event_class = ffi::bt_event_class_create(stream_class);
            let ret =
                ffi::bt_event_class_set_name(event_class, b"irq_handler_entry\0".as_ptr() as _);
            ret.capi_result()?;

            let payload_fc = ffi::bt_field_class_structure_create(trace_class);

            let fc = ffi::bt_field_class_string_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"src_event_type\0".as_ptr() as _,
                fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(fc);

            let fc = ffi::bt_field_class_integer_signed_create(trace_class);
            let ret =
                ffi::bt_field_class_structure_append_member(payload_fc, b"irq\0".as_ptr() as _, fc);
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(fc);

            let fc = ffi::bt_field_class_string_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"name\0".as_ptr() as _,
                fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(fc);

            let fc = ffi::bt_field_class_integer_signed_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"prio\0".as_ptr() as _,
                fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(fc);

            let ret = ffi::bt_event_class_set_payload_field_class(event_class, payload_fc);
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(payload_fc);

            Ok(event_class)
        }
    }

    pub fn event(
        event: &IsrEvent,
        src_event_type_str: *const i8, // TODO
        string_cache: &mut StringCache,
        ctf_event: *mut ffi::bt_event,
    ) -> Result<(), Error> {
        unsafe {
            let payload_f = ffi::bt_event_borrow_payload_field(ctf_event);

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 0);
            let ret = ffi::bt_field_string_set_value(f, src_event_type_str);
            ret.capi_result()?;

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 1);
            ffi::bt_field_integer_signed_set_value(f, u32::from(event.handle).into());

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 2);
            let n = string_cache.get_or_insert(&event.name)?;
            let ret = ffi::bt_field_string_set_value(f, n.as_c_str().as_ptr() as _);
            ret.capi_result()?;

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 3);
            ffi::bt_field_integer_signed_set_value(f, u32::from(event.priority).into());

            Ok(())
        }
    }
}

mod irq_handler_exit {
    use super::*;

    pub fn event_class(
        stream_class: *mut ffi::bt_stream_class,
    ) -> Result<*mut ffi::bt_event_class, Error> {
        unsafe {
            let trace_class = ffi::bt_stream_class_borrow_trace_class(stream_class);

            let event_class = ffi::bt_event_class_create(stream_class);
            let ret =
                ffi::bt_event_class_set_name(event_class, b"irq_handler_exit\0".as_ptr() as _);
            ret.capi_result()?;

            let payload_fc = ffi::bt_field_class_structure_create(trace_class);

            let fc = ffi::bt_field_class_string_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"src_event_type\0".as_ptr() as _,
                fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(fc);

            let fc = ffi::bt_field_class_integer_signed_create(trace_class);
            let ret =
                ffi::bt_field_class_structure_append_member(payload_fc, b"irq\0".as_ptr() as _, fc);
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(fc);

            let fc = ffi::bt_field_class_integer_signed_create(trace_class);
            let ret =
                ffi::bt_field_class_structure_append_member(payload_fc, b"ret\0".as_ptr() as _, fc);
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(fc);

            let ret = ffi::bt_event_class_set_payload_field_class(event_class, payload_fc);
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(payload_fc);

            Ok(event_class)
        }
    }

    pub fn event(
        isr_handle: ObjectHandle,
        src_event_type_str: *const i8, // TODO
        ctf_event: *mut ffi::bt_event,
    ) -> Result<(), Error> {
        unsafe {
            let payload_f = ffi::bt_event_borrow_payload_field(ctf_event);

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 0);
            let ret = ffi::bt_field_string_set_value(f, src_event_type_str);
            ret.capi_result()?;

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 1);
            ffi::bt_field_integer_signed_set_value(f, u32::from(isr_handle).into());

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 2);
            ffi::bt_field_integer_signed_set_value(f, 1); // was-handled

            Ok(())
        }
    }
}

mod sched_wakeup {
    use super::*;

    pub fn event_class(
        stream_class: *mut ffi::bt_stream_class,
    ) -> Result<*mut ffi::bt_event_class, Error> {
        unsafe {
            let trace_class = ffi::bt_stream_class_borrow_trace_class(stream_class);

            let event_class = ffi::bt_event_class_create(stream_class);
            let ret = ffi::bt_event_class_set_name(event_class, b"sched_wakeup\0".as_ptr() as _);
            ret.capi_result()?;

            let payload_fc = ffi::bt_field_class_structure_create(trace_class);

            let fc = ffi::bt_field_class_string_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"src_event_type\0".as_ptr() as _,
                fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(fc);

            let fc = ffi::bt_field_class_string_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"comm\0".as_ptr() as _,
                fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(fc);

            let fc = ffi::bt_field_class_integer_signed_create(trace_class);
            let ret =
                ffi::bt_field_class_structure_append_member(payload_fc, b"tid\0".as_ptr() as _, fc);
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(fc);

            let fc = ffi::bt_field_class_integer_signed_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"prio\0".as_ptr() as _,
                fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(fc);

            let fc = ffi::bt_field_class_integer_signed_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                payload_fc,
                b"target_cpu\0".as_ptr() as _,
                fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(fc);

            let ret = ffi::bt_event_class_set_payload_field_class(event_class, payload_fc);
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(payload_fc);

            Ok(event_class)
        }
    }

    pub fn event(
        event: &TaskEvent,
        src_event_type_str: *const i8, // TODO
        string_cache: &mut StringCache,
        ctf_event: *mut ffi::bt_event,
    ) -> Result<(), Error> {
        unsafe {
            let payload_f = ffi::bt_event_borrow_payload_field(ctf_event);

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 0);
            let ret = ffi::bt_field_string_set_value(f, src_event_type_str);
            ret.capi_result()?;

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 1);
            let n = string_cache.get_or_insert(&event.name)?;
            let ret = ffi::bt_field_string_set_value(f, n.as_c_str().as_ptr() as _);
            ret.capi_result()?;

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 2);
            ffi::bt_field_integer_signed_set_value(f, u32::from(event.handle).into());

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 3);
            ffi::bt_field_integer_signed_set_value(f, u32::from(event.priority).into());

            let f = ffi::bt_field_structure_borrow_member_field_by_index(payload_f, 4);
            ffi::bt_field_integer_signed_set_value(f, 0); // target_cpu

            Ok(())
        }
    }
}
