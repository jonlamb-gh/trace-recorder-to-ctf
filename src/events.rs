use crate::types::{Context, StringCache};
use babeltrace2_sys::Error;
use ctf_macros::CtfEventClass;
use enum_iterator::Sequence;
use std::convert::TryFrom;
use std::ffi::CStr;
use trace_recorder_parser::{streaming::event::*, types::UserEventChannel};

// TODO - any way to use serde-reflection to synthesize these?

#[derive(CtfEventClass)]
#[event_name = "TRACE_START"]
pub struct TraceStart<'a> {
    pub task_handle: i64,
    pub task: &'a CStr,
}

impl<'a> TryFrom<(&TraceStartEvent, &'a mut StringCache)> for TraceStart<'a> {
    type Error = Error;

    fn try_from(value: (&TraceStartEvent, &'a mut StringCache)) -> Result<Self, Self::Error> {
        value.1.insert_str(&value.0.current_task)?;
        Ok(Self {
            task_handle: u32::from(value.0.current_task_handle).into(),
            task: value.1.get_str(value.0.current_task.as_ref()),
        })
    }
}

#[derive(CtfEventClass)]
#[event_name = "UNKNOWN"]
pub struct Unknown<'a> {
    pub event_type: &'a CStr,
}

impl<'a> TryFrom<(EventType, &'a mut StringCache)> for Unknown<'a> {
    type Error = Error;

    fn try_from(value: (EventType, &'a mut StringCache)) -> Result<Self, Self::Error> {
        value.1.insert_type(value.0)?;
        Ok(Self {
            event_type: value.1.get_type(&value.0),
        })
    }
}

#[derive(CtfEventClass)]
#[event_name = "USER_EVENT"]
pub struct User<'a> {
    pub channel: &'a CStr,
    pub format_string: &'a CStr,
    pub formatted_string: &'a CStr,
    // TODO args
}

impl<'a> TryFrom<(&UserEvent, &'a mut StringCache)> for User<'a> {
    type Error = Error;

    fn try_from(value: (&UserEvent, &'a mut StringCache)) -> Result<Self, Self::Error> {
        let ch = match &value.0.channel {
            UserEventChannel::Default => UserEventChannel::DEFAULT,
            UserEventChannel::Custom(c) => c.as_str(),
        };
        value.1.insert_str(ch)?;
        value.1.insert_str(&value.0.format_string)?;
        value.1.insert_str(&value.0.formatted_string)?;
        Ok(Self {
            channel: value.1.get_str(ch),
            format_string: value.1.get_str(&value.0.format_string),
            formatted_string: value.1.get_str(&value.0.formatted_string),
        })
    }
}

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

#[derive(CtfEventClass)]
#[event_name = "sched_switch"]
pub struct SchedSwitch<'a> {
    pub src_event_type: &'a CStr,
    pub prev_comm: &'a CStr,
    pub prev_tid: i64,
    pub prev_prio: i64,
    pub prev_state: TaskState,
    pub next_comm: &'a CStr,
    pub next_tid: i64,
    pub next_prio: i64,
}

impl<'a> TryFrom<(EventType, &Context, &Context, &'a mut StringCache)> for SchedSwitch<'a> {
    type Error = Error;

    fn try_from(
        value: (EventType, &Context, &Context, &'a mut StringCache),
    ) -> Result<Self, Self::Error> {
        let event_type = value.0;
        let prev_ctx = value.1;
        let next_ctx = value.2;
        let cache = value.3;
        cache.insert_type(event_type)?;
        cache.insert_str(&prev_ctx.name)?;
        cache.insert_str(&next_ctx.name)?;
        Ok(Self {
            src_event_type: cache.get_type(&event_type),
            prev_comm: cache.get_str(&prev_ctx.name),
            prev_tid: u32::from(prev_ctx.handle).into(),
            prev_prio: u32::from(prev_ctx.priority).into(),
            prev_state: TaskState::Running, // TODO always running?
            next_comm: cache.get_str(&next_ctx.name),
            next_tid: u32::from(next_ctx.handle).into(),
            next_prio: u32::from(next_ctx.priority).into(),
        })
    }
}

#[derive(CtfEventClass)]
#[event_name = "sched_wakeup"]
pub struct SchedWakeup<'a> {
    pub src_event_type: &'a CStr,
    pub comm: &'a CStr,
    pub tid: i64,
    pub prio: i64,
    pub target_cpu: i64,
}

impl<'a> TryFrom<(EventType, &TaskEvent, &'a mut StringCache)> for SchedWakeup<'a> {
    type Error = Error;

    fn try_from(value: (EventType, &TaskEvent, &'a mut StringCache)) -> Result<Self, Self::Error> {
        value.2.insert_type(value.0)?;
        value.2.insert_str(&value.1.name)?;
        Ok(Self {
            src_event_type: value.2.get_type(&value.0),
            comm: value.2.get_str(&value.1.name),
            tid: u32::from(value.1.handle).into(),
            prio: u32::from(value.1.priority).into(),
            target_cpu: 0,
        })
    }
}

#[derive(CtfEventClass)]
#[event_name = "irq_handler_entry"]
pub struct IrqHandlerEntry<'a> {
    pub src_event_type: &'a CStr,
    pub irq: i64,
    pub name: &'a CStr,
    pub prio: i64,
}

impl<'a> TryFrom<(EventType, &IsrEvent, &'a mut StringCache)> for IrqHandlerEntry<'a> {
    type Error = Error;

    fn try_from(value: (EventType, &IsrEvent, &'a mut StringCache)) -> Result<Self, Self::Error> {
        value.2.insert_type(value.0)?;
        value.2.insert_str(&value.1.name)?;
        Ok(Self {
            src_event_type: value.2.get_type(&value.0),
            irq: u32::from(value.1.handle).into(),
            name: value.2.get_str(&value.1.name),
            prio: u32::from(value.1.priority).into(),
        })
    }
}

#[derive(CtfEventClass)]
#[event_name = "irq_handler_exit"]
pub struct IrqHandlerExit<'a> {
    pub src_event_type: &'a CStr,
    pub irq: i64,
    pub name: &'a CStr,
    pub ret: i64,
}

impl<'a> TryFrom<(EventType, &Context, &'a mut StringCache)> for IrqHandlerExit<'a> {
    type Error = Error;

    fn try_from(value: (EventType, &Context, &'a mut StringCache)) -> Result<Self, Self::Error> {
        value.2.insert_type(value.0)?;
        value.2.insert_str(&value.1.name)?;
        Ok(Self {
            src_event_type: value.2.get_type(&value.0),
            irq: u32::from(value.1.handle).into(),
            name: value.2.get_str(&value.1.name),
            ret: 1, // was-handled
        })
    }
}

#[derive(CtfEventClass)]
#[event_name_from_event_type]
pub struct Unsupported {
    // No payload fields
}
