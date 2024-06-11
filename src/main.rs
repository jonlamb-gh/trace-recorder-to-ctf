use crate::{convert::TrcCtfConverter, types::BorrowedCtfState};
use babeltrace2_sys::{
    ffi, source_plugin_descriptors, BtResult, BtResultExt, CtfPluginSinkFsInitParams,
    EncoderPipeline, Error, LoggingLevel, MessageIteratorStatus, Plugin, RunStatus, SelfComponent,
    SelfMessageIterator, SourcePluginDescriptor, SourcePluginHandler,
};
use chrono::prelude::{DateTime, Utc};
use clap::Parser;
use interruptor::Interruptor;
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::BufReader,
    path::PathBuf,
    ptr,
};
use trace_recorder_parser::{
    streaming::event::{Event, EventCode, EventType, TrackingEventCounter},
    streaming::RecorderData,
    time::StreamingInstant,
};
use tracing::{debug, error, info, warn};

mod convert;
mod events;
mod interruptor;
mod types;

/// Convert FreeRTOS trace-recorder traces to CTF
#[derive(Parser, Debug, Clone)]
#[clap(version)]
pub struct Opts {
    /// The CTF clock class name
    #[clap(long, default_value = "monotonic")]
    pub clock_name: String,

    /// The CTF trace name
    #[clap(long, default_value = "freertos")]
    pub trace_name: String,

    /// babeltrace2 log level
    #[clap(long, default_value = "warn")]
    pub log_level: LoggingLevel,

    /// Output directory to write traces to
    #[clap(short = 'o', long, default_value = "ctf_trace")]
    pub output: PathBuf,

    /// Path to the input trace recorder binary file (psf) to read
    pub input: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match do_main() {
        Err(e) => {
            error!("{}", e);
            Err(e)
        }
        Ok(()) => Ok(()),
    }
}

fn do_main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();

    let intr = Interruptor::new();
    let intr_clone = intr.clone();
    ctrlc::set_handler(move || {
        if intr_clone.is_set() {
            let exit_code = if cfg!(target_family = "unix") {
                // 128 (fatal error signal "n") + 2 (control-c is fatal error signal 2)
                130
            } else {
                // Windows code 3221225786
                // -1073741510 == C000013A
                -1073741510
            };
            std::process::exit(exit_code);
        }

        debug!("Shutdown signal received");
        intr_clone.set();
    })?;

    info!(input = %opts.input.display(), "Reading header info");
    let file = File::open(&opts.input)?;
    let mut reader = BufReader::new(file);

    let trd = RecorderData::find(&mut reader)?;

    let output_path = CString::new(opts.output.to_str().unwrap())?;
    let params = CtfPluginSinkFsInitParams::new(
        Some(true), // assume_single_trace
        None,       // ignore_discarded_events
        None,       // ignore_discarded_packets
        Some(true), // quiet
        &output_path,
    )?;

    let state_inner: Box<dyn SourcePluginHandler> =
        Box::new(TrcPluginState::new(intr, reader, trd, &opts)?);
    let state = Box::new(state_inner);

    let mut pipeline = EncoderPipeline::new::<TrcPlugin>(opts.log_level, state, &params)?;

    loop {
        let run_status = pipeline.graph.run_once()?;
        if RunStatus::End == run_status {
            break;
        }
    }

    info!("Done");

    Ok(())
}

struct TrcPluginState {
    interruptor: Interruptor,
    reader: BufReader<File>,
    clock_name: CString,
    trace_name: CString,
    input_file_name: CString,
    trace_creation_time: DateTime<Utc>,
    trd: RecorderData,
    first_event_observed: bool,
    eof_reached: bool,
    stream_is_open: bool,
    time_rollover_tracker: StreamingInstant,
    event_counter_tracker: TrackingEventCounter,
    stream: *mut ffi::bt_stream,
    packet: *mut ffi::bt_packet,
    converter: TrcCtfConverter,
}

impl TrcPluginState {
    fn new(
        interruptor: Interruptor,
        reader: BufReader<File>,
        trd: RecorderData,
        opts: &Opts,
    ) -> Result<Self, Error> {
        let clock_name = CString::new(opts.clock_name.as_str())?;
        let trace_name = CString::new(opts.trace_name.as_str())?;
        let input_file_name = CString::new(opts.input.file_name().unwrap().to_str().unwrap())?;
        Ok(Self {
            interruptor,
            reader,
            clock_name,
            trace_name,
            input_file_name,
            trace_creation_time: Utc::now(),
            trd,
            first_event_observed: false,
            eof_reached: false,
            stream_is_open: false,
            // NOTE: timestamp/event trackers get re-initialized on the first event
            time_rollover_tracker: StreamingInstant::zero(),
            event_counter_tracker: TrackingEventCounter::zero(),
            stream: ptr::null_mut(),
            packet: ptr::null_mut(),
            converter: TrcCtfConverter::new(),
        })
    }

    fn create_metadata_and_stream_objects(
        &mut self,
        mut component: SelfComponent,
    ) -> Result<(), Error> {
        unsafe {
            let trace_class = ffi::bt_trace_class_create(component.inner_mut());

            // Create common event context
            let base_event_context = self.converter.create_event_common_context(trace_class)?;

            // Setup the default clock class
            let clock_class = ffi::bt_clock_class_create(component.inner_mut());
            let ret =
                ffi::bt_clock_class_set_name(clock_class, self.clock_name.as_c_str().as_ptr());
            ret.capi_result()?;
            ffi::bt_clock_class_set_frequency(
                clock_class,
                self.trd.timestamp_info.timer_frequency.get_raw() as _,
            );
            ffi::bt_clock_class_set_origin_is_unix_epoch(clock_class, 0);

            let stream_class = ffi::bt_stream_class_create(trace_class);
            ffi::bt_stream_class_set_default_clock_class(stream_class, clock_class);
            ffi::bt_stream_class_set_supports_packets(
                stream_class,
                1, //supports_packets
                0, // with_beginning_default_clock_snapshot
                0, // with_end_default_clock_snapshot
            );
            ffi::bt_stream_class_set_supports_discarded_packets(
                stream_class,
                0, // supports_discarded_packets
                0, // with_default_clock_snapshots
            );
            ffi::bt_stream_class_set_supports_discarded_events(
                stream_class,
                1, // supports_discarded_events
                0, // with_default_clock_snapshots
            );
            let ret = ffi::bt_stream_class_set_event_common_context_field_class(
                stream_class,
                base_event_context,
            );
            ret.capi_result()?;

            // Add cpu_id packet context
            let packet_context_fc = ffi::bt_field_class_structure_create(trace_class);
            let cpu_id_fc = ffi::bt_field_class_integer_unsigned_create(trace_class);
            let ret = ffi::bt_field_class_structure_append_member(
                packet_context_fc,
                b"cpu_id\0".as_ptr() as _,
                cpu_id_fc,
            );
            ret.capi_result()?;
            let ret = ffi::bt_stream_class_set_packet_context_field_class(
                stream_class,
                packet_context_fc,
            );
            ret.capi_result()?;
            ffi::bt_field_class_put_ref(cpu_id_fc);
            ffi::bt_field_class_put_ref(packet_context_fc);

            let trace = ffi::bt_trace_create(trace_class);
            ffi::bt_trace_set_name(trace, self.trace_name.as_c_str().as_ptr());

            self.stream = ffi::bt_stream_create(stream_class, trace);
            self.create_new_packet()?;

            // Put the references we don't need anymore
            ffi::bt_trace_put_ref(trace);
            ffi::bt_clock_class_put_ref(clock_class);
            ffi::bt_stream_class_put_ref(stream_class);
            ffi::bt_trace_class_put_ref(trace_class as *const _);
            ffi::bt_field_class_put_ref(base_event_context);
        }

        Ok(())
    }

    fn set_trace_env(&mut self) -> Result<(), Error> {
        unsafe {
            let trace = ffi::bt_stream_borrow_trace(self.stream);
            let ret = ffi::bt_trace_set_environment_entry_string(
                trace,
                b"hostname\0".as_ptr() as _,
                b"trace-recorder\0".as_ptr() as _,
            );
            ret.capi_result()?;
            let ret = ffi::bt_trace_set_environment_entry_string(
                trace,
                b"domain\0".as_ptr() as _,
                b"kernel\0".as_ptr() as _,
            );
            ret.capi_result()?;
            let ret = ffi::bt_trace_set_environment_entry_string(
                trace,
                b"tracer_name\0".as_ptr() as _,
                b"lttng-modules\0".as_ptr() as _,
            );
            ret.capi_result()?;
            let ret = ffi::bt_trace_set_environment_entry_integer(
                trace,
                b"tracer_major\0".as_ptr() as _,
                2,
            );
            ret.capi_result()?;
            let ret = ffi::bt_trace_set_environment_entry_integer(
                trace,
                b"tracer_minor\0".as_ptr() as _,
                12,
            );
            ret.capi_result()?;
            let ret = ffi::bt_trace_set_environment_entry_integer(
                trace,
                b"tracer_patchlevel\0".as_ptr() as _,
                5,
            );
            ret.capi_result()?;
            let ret = ffi::bt_trace_set_environment_entry_string(
                trace,
                b"trace_buffering_scheme\0".as_ptr() as _,
                b"global\0".as_ptr() as _,
            );
            ret.capi_result()?;
            let val = CString::new(self.trd.header.endianness.to_string())?;
            let ret = ffi::bt_trace_set_environment_entry_string(
                trace,
                b"trc_endianness\0".as_ptr() as _,
                val.as_c_str().as_ptr(),
            );
            ret.capi_result()?;
            let ret = ffi::bt_trace_set_environment_entry_integer(
                trace,
                b"trc_format_version\0".as_ptr() as _,
                self.trd.header.format_version.into(),
            );
            ret.capi_result()?;
            let val = CString::new(format!("{:X?}", self.trd.header.kernel_version))?;
            let ret = ffi::bt_trace_set_environment_entry_string(
                trace,
                b"trc_kernel_version\0".as_ptr() as _,
                val.as_c_str().as_ptr(),
            );
            ret.capi_result()?;
            let val = CString::new(self.trd.header.kernel_port.to_string())?;
            let ret = ffi::bt_trace_set_environment_entry_string(
                trace,
                b"trc_kernel_port\0".as_ptr() as _,
                val.as_c_str().as_ptr(),
            );
            ret.capi_result()?;
            let val = CString::new(self.trd.header.platform_cfg.to_string())?;
            let ret = ffi::bt_trace_set_environment_entry_string(
                trace,
                b"trc_platform_cfg\0".as_ptr() as _,
                val.as_c_str().as_ptr(),
            );
            ret.capi_result()?;
            let val = CString::new(self.trd.header.platform_cfg_version.to_string())?;
            let ret = ffi::bt_trace_set_environment_entry_string(
                trace,
                b"trc_platform_cfg_version\0".as_ptr() as _,
                val.as_c_str().as_ptr(),
            );
            ret.capi_result()?;
            let ret = ffi::bt_trace_set_environment_entry_string(
                trace,
                b"input_file\0".as_ptr() as _,
                self.input_file_name.as_c_str().as_ptr(),
            );
            ret.capi_result()?;
            let val = CString::new(format!(
                "{}",
                self.trace_creation_time.format("%Y%m%dT%H%M%S+0000")
            ))?;
            let ret = ffi::bt_trace_set_environment_entry_string(
                trace,
                b"trace_creation_datetime\0".as_ptr() as _,
                val.as_c_str().as_ptr(),
            );
            ret.capi_result()?;
            let val = CString::new(format!("{}", self.trace_creation_time))?;
            let ret = ffi::bt_trace_set_environment_entry_string(
                trace,
                b"trace_creation_datetime_utc\0".as_ptr() as _,
                val.as_c_str().as_ptr(),
            );
            ret.capi_result()?;
        }
        Ok(())
    }

    fn create_new_packet(&mut self) -> Result<(), Error> {
        unsafe {
            if !self.packet.is_null() {
                ffi::bt_packet_put_ref(self.packet);
            }

            self.packet = ffi::bt_packet_create(self.stream);

            let packet_ctx_f = ffi::bt_packet_borrow_context_field(self.packet);
            let cpu_id_f = ffi::bt_field_structure_borrow_member_field_by_index(packet_ctx_f, 0);
            ffi::bt_field_integer_unsigned_set_value(cpu_id_f, 0);
        }
        Ok(())
    }

    fn read_event(&mut self) -> Result<Option<(EventCode, Event)>, Error> {
        if self.eof_reached {
            return Ok(None);
        }

        match self.trd.read_event(&mut self.reader) {
            Ok(Some(ev)) => Ok(Some(ev)),
            Ok(None) => Ok(None),
            Err(e) => {
                use trace_recorder_parser::streaming::Error as TrcError;

                match e {
                    // TODO - this should probably start a new packet
                    TrcError::TraceRestarted(psf_start_word_endianness) => {
                        warn!("Detected a restarted trace stream");
                        self.trd = RecorderData::read_with_endianness(
                            psf_start_word_endianness,
                            &mut self.reader,
                        )
                        .map_err(|e| Error::PluginError(e.to_string()))?;
                        self.first_event_observed = false;
                        Ok(None)
                    }
                    _ => {
                        warn!(%e, "Data error");
                        Ok(None)
                    }
                }
            }
        }
    }

    fn process_event(
        &mut self,
        event_code: EventCode,
        event: Event,
        ctf_state: &mut BorrowedCtfState,
    ) -> Result<(), Error> {
        let event_type = event_code.event_type();

        let dropped_events = if !self.first_event_observed {
            self.first_event_observed = true;

            if event_type != EventType::TraceStart {
                warn!(%event_type, "First event should be TRACE_START");
            }

            self.event_counter_tracker
                .set_initial_count(event.event_count());
            self.time_rollover_tracker = StreamingInstant::new(
                event.timestamp().ticks() as u32,
                self.trd.timestamp_info.timer_wraparounds,
            );

            None
        } else {
            self.event_counter_tracker.update(event.event_count())
        };

        if let Some(dropped_events) = dropped_events {
            warn!(
                event_count = %event.event_count(),
                dropped_events, "Detected dropped events"
            );
            let msg = unsafe {
                ffi::bt_message_discarded_events_create(
                    ctf_state.message_iter_mut(),
                    ctf_state.stream_mut(),
                )
            };
            unsafe { ffi::bt_message_discarded_events_set_count(msg, dropped_events) };
            ctf_state.push_message(msg)?;
        }

        // Update timer/counter rollover trackers
        let event_count = self.event_counter_tracker.count();
        let timestamp = self.time_rollover_tracker.elapsed(event.timestamp());

        self.converter
            .convert(event_code, event_count, timestamp, event, ctf_state)?;

        Ok(())
    }
}

impl SourcePluginHandler for TrcPluginState {
    fn initialize(&mut self, component: SelfComponent) -> Result<(), Error> {
        self.create_metadata_and_stream_objects(component)?;
        self.set_trace_env()?;

        assert!(!self.stream.is_null());
        self.converter.create_event_classes(self.stream)?;

        Ok(())
    }

    fn finalize(&mut self, _component: SelfComponent) -> Result<(), Error> {
        unsafe {
            assert!(!self.packet.is_null());
            ffi::bt_packet_put_ref(self.packet);
            self.packet = ptr::null_mut();

            assert!(!self.stream.is_null());
            ffi::bt_stream_put_ref(self.stream);
            self.stream = ptr::null_mut();
        }

        Ok(())
    }

    fn iterator_next(
        &mut self,
        msg_iter: SelfMessageIterator,
        messages: &mut [*const ffi::bt_message],
    ) -> Result<MessageIteratorStatus, Error> {
        assert!(!self.stream.is_null());

        let mut ctf_state = BorrowedCtfState::new(self.stream, self.packet, msg_iter, messages);

        if self.interruptor.is_set() & !self.eof_reached {
            debug!("Early shutdown");
            self.eof_reached = true;

            // Add packet end message
            let msg = unsafe {
                ffi::bt_message_packet_end_create(ctf_state.message_iter_mut(), self.packet)
            };
            ctf_state.push_message(msg)?;

            // Add stream end message
            let msg = unsafe {
                ffi::bt_message_stream_end_create(ctf_state.message_iter_mut(), self.stream)
            };
            ctf_state.push_message(msg)?;

            return Ok(ctf_state.release());
        }

        match self.read_event()? {
            Some((event_code, event)) => {
                if !self.stream_is_open {
                    debug!("Opening stream");
                    self.stream_is_open = true;

                    // Add stream begin message
                    let msg = unsafe {
                        ffi::bt_message_stream_beginning_create(
                            ctf_state.message_iter_mut(),
                            self.stream,
                        )
                    };
                    ctf_state.push_message(msg)?;

                    // Add packet begin message
                    let msg = unsafe {
                        ffi::bt_message_packet_beginning_create(
                            ctf_state.message_iter_mut(),
                            self.packet,
                        )
                    };
                    ctf_state.push_message(msg)?;
                }

                // TODO need to put_ref(msg) on this and/or all of the msgs?
                self.process_event(event_code, event, &mut ctf_state)?;

                Ok(ctf_state.release())
            }
            None => {
                if self.stream_is_open && !self.first_event_observed {
                    // Trace restart condition
                    Ok(MessageIteratorStatus::NoMessages)
                } else if self.eof_reached {
                    // Last iteration can't have messages
                    Ok(MessageIteratorStatus::Done)
                } else {
                    debug!("End of file reached");
                    self.eof_reached = true;

                    // Add packet end message
                    let msg = unsafe {
                        ffi::bt_message_packet_end_create(ctf_state.message_iter_mut(), self.packet)
                    };
                    ctf_state.push_message(msg)?;

                    // Add stream end message
                    let msg = unsafe {
                        ffi::bt_message_stream_end_create(ctf_state.message_iter_mut(), self.stream)
                    };
                    ctf_state.push_message(msg)?;

                    Ok(ctf_state.release())
                }
            }
        }
    }
}

struct TrcPlugin;

impl SourcePluginDescriptor for TrcPlugin {
    /// Provides source.trace-recorder.output
    const PLUGIN_NAME: &'static [u8] = b"trace-recorder\0";
    const OUTPUT_COMP_NAME: &'static [u8] = b"output\0";
    const GRAPH_NODE_NAME: &'static [u8] = b"source.trace-recorder.output\0";

    fn load() -> BtResult<Plugin> {
        let name = Self::plugin_name();
        Plugin::load_from_statics_by_name(name)
    }

    fn plugin_name() -> &'static CStr {
        unsafe { CStr::from_bytes_with_nul_unchecked(Self::PLUGIN_NAME) }
    }

    fn output_name() -> &'static CStr {
        unsafe { CStr::from_bytes_with_nul_unchecked(Self::OUTPUT_COMP_NAME) }
    }

    fn graph_node_name() -> &'static CStr {
        unsafe { CStr::from_bytes_with_nul_unchecked(Self::GRAPH_NODE_NAME) }
    }
}

source_plugin_descriptors!(TrcPlugin);

pub mod utils_plugin_descriptors {
    use babeltrace2_sys::ffi::*;

    #[link(
        name = "babeltrace-plugin-utils",
        kind = "static",
        modifiers = "+whole-archive"
    )]
    extern "C" {
        pub static __bt_plugin_descriptor_auto_ptr: *const __bt_plugin_descriptor;
    }
}

pub mod ctf_plugin_descriptors {
    use babeltrace2_sys::ffi::*;

    #[link(
        name = "babeltrace-plugin-ctf",
        kind = "static",
        modifiers = "+whole-archive"
    )]
    extern "C" {
        pub static __bt_plugin_descriptor_auto_ptr: *const __bt_plugin_descriptor;
    }
}
