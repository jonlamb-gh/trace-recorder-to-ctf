use crate::events::*;
use crate::types::{BorrowedCtfState, Context, StringCache};
use babeltrace2_sys::{ffi, BtResultExt, Error};
use std::collections::{hash_map::Entry, HashMap};
use std::ptr;
use trace_recorder_parser::{streaming::event::*, time::Timestamp, types::*};
use tracing::warn;

pub struct TrcCtfConverter {
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
        self.unknown_event_class = Unknown::event_class(stream_class)?;
        self.user_event_class = User::event_class(stream_class)?;
        self.sched_switch_event_class = SchedSwitch::event_class(stream_class)?;
        self.irq_handler_entry_event_class = IrqHandlerEntry::event_class(stream_class)?;
        self.irq_handler_exit_event_class = IrqHandlerExit::event_class(stream_class)?;
        self.sched_wakeup_event_class = SchedWakeup::event_class(stream_class)?;
        Ok(())
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
        event: Event,
        ctf_state: &mut BorrowedCtfState,
    ) -> Result<(), Error> {
        let event_id = event_code.event_id();
        let event_type = event_code.event_type();
        let raw_timestamp = event.timestamp();

        let stream_class = unsafe { ffi::bt_stream_borrow_class(ctf_state.stream_mut()) };

        match event {
            Event::TraceStart(ev) => {
                let event_class =
                    self.event_class(stream_class, event_type, TraceStart::event_class)?;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                TraceStart::try_from((&ev, &mut self.string_cache))?.emit_event(ctf_event)?;
                ctf_state.push_message(msg)?;
            }

            Event::Unknown(_) => {
                let event_class = self.unknown_event_class;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                Unknown::try_from((event_type, &mut self.string_cache))?.emit_event(ctf_event)?;
                ctf_state.push_message(msg)?;
            }

            Event::User(ev) => {
                let event_class = self.user_event_class;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                User::try_from((&ev, &mut self.string_cache))?.emit_event(ctf_event)?;
                ctf_state.push_message(msg)?;
            }

            Event::TaskReady(ev) => {
                let event_class = self.sched_wakeup_event_class;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                SchedWakeup::try_from((event_type, &ev, &mut self.string_cache))?
                    .emit_event(ctf_event)?;
                ctf_state.push_message(msg)?;
            }

            Event::TaskResume(ev) | Event::TaskActivate(ev) => {
                // Check for return from ISR
                if let Some(isr) = self.pending_isrs.pop() {
                    // TODO should sched_switch be created if on the same context?
                    // depends on the arg given to xTraceISREnd(arg)
                    let event_class = self.irq_handler_exit_event_class;
                    let msg = ctf_state.create_message(event_class, tracked_timestamp);
                    let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                    self.add_event_common_ctx(
                        event_id,
                        tracked_event_count,
                        raw_timestamp,
                        ctf_event,
                    )?;
                    let ctx = isr;
                    IrqHandlerExit::try_from((event_type, &ctx, &mut self.string_cache))?
                        .emit_event(ctf_event)?;
                    ctf_state.push_message(msg)?;
                }

                let event_class = self.sched_switch_event_class;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                let next_ctx = Context::from(ev);
                let prev_ctx = &self.active_context;
                SchedSwitch::try_from((event_type, prev_ctx, &next_ctx, &mut self.string_cache))?
                    .emit_event(ctf_event)?;
                self.active_context = next_ctx;
                ctf_state.push_message(msg)?;
            }

            Event::IsrBegin(ev) => {
                let context = Context {
                    handle: ev.handle,
                    name: ev.name.clone(),
                    priority: ev.priority,
                };
                self.pending_isrs.push(context);
                let event_class = self.irq_handler_entry_event_class;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                IrqHandlerEntry::try_from((event_type, &ev, &mut self.string_cache))?
                    .emit_event(ctf_event)?;
                ctf_state.push_message(msg)?;
            }

            // Return to the interrupted ISR (nested ISR)
            Event::IsrResume(ev) if !self.pending_isrs.is_empty() => {
                // This event indicates the previous ISR context before the active context
                // top of the stack contains the active context
                let ctx = self.pending_isrs.pop().unwrap();
                let previous_isr = self.pending_isrs.last();
                let previous_ctx = Context::from(ev);
                assert_eq!(Some(&previous_ctx), previous_isr);

                let event_class = self.irq_handler_exit_event_class;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                IrqHandlerExit::try_from((event_type, &ctx, &mut self.string_cache))?
                    .emit_event(ctf_event)?;
                ctf_state.push_message(msg)?;
            }

            // The rest are named events with no payload
            _ => {
                if let Event::IsrResume(ev) = event {
                    warn!(%event_type, event = %ev, "Got ISR resume but no pending IRS");
                }

                let event_class = self.event_class(stream_class, event_type, |stream_class| {
                    Unsupported::event_class(event_type, stream_class)
                })?;
                let msg = ctf_state.create_message(event_class, tracked_timestamp);
                let ctf_event = unsafe { ffi::bt_message_event_borrow_event(msg) };
                self.add_event_common_ctx(event_id, tracked_event_count, raw_timestamp, ctf_event)?;
                Unsupported {}.emit_event(ctf_event)?;
                ctf_state.push_message(msg)?;
            }
        }

        Ok(())
    }
}
