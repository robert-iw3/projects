#![no_std]
#![feature(alloc_error_handler)]
// Enable feature gates
#![cfg_attr(any(feature = "registry", feature = "threads", feature = "objects", feature = "memory", feature = "power", feature = "ai_agent"), allow(unused))]

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};
use core::ffi::c_void;
use wdk_sys::*;
use wdk_sys::ntddk::*;
use wdk_sys::ntifs::*;
use wdk_alloc::WdkAllocator;
use wdk_panic;

#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

// --- Constants & Context Tags ---
const TAG_CONTEXT: u32 = u32::from_le_bytes(*b"monC");
const MAX_EVENTS: usize = 1024; // Power of 2 for efficient wrapping

// --- Data Structures ---

// ML-Ready Event Struct (Must match User Mode)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MonitorEvent {
    pub event_type: u32,      // 0:Proc, 1-3:File, 4:Reg, 7:Thread, 8:Obj
    pub pid: HANDLE,
    pub parent_pid: HANDLE,
    pub timestamp: LARGE_INTEGER,
    pub path_len: u16,
    pub path: [WCHAR; 260],
    pub anomaly_score_fixed: u32, // Fixed-point: Score * 1000. 850 = 0.85
    pub syscall_id: u32,
    pub event_id: u64,
    pub hash: [u8; 32],
    pub activity_id: GUID,
    pub cloud_context: [u8; 64],
}

// Stream Context for Caching File Names
#[repr(C)]
pub struct MonitorStreamContext {
    pub name_len: u16,
    pub name: [WCHAR; 260],
}

// --- Global State ---

static mut EVENT_QUEUE: [MonitorEvent; MAX_EVENTS] = [MonitorEvent {
    event_type: 0, pid: core::ptr::null_mut(), parent_pid: core::ptr::null_mut(), timestamp: LARGE_INTEGER { QuadPart: 0 },
    path_len: 0, path: [0; 260], anomaly_score_fixed: 0, syscall_id: 0, event_id: 0, hash: [0; 32],
    activity_id: GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] }, cloud_context: [0; 64],
}; MAX_EVENTS];

static QUEUE_HEAD: AtomicUsize = AtomicUsize::new(0);
static QUEUE_TAIL: AtomicUsize = AtomicUsize::new(0);
static mut QUEUE_LOCK: KSPIN_LOCK = 0;

static mut FILTER_HANDLE: PFLT_FILTER = core::ptr::null_mut();
static mut REG_COOKIE: EX_COOKIE = EX_COOKIE { LinkedList: LIST_ENTRY { Flink: core::ptr::null_mut(), Blink: core::ptr::null_mut() } };

#[cfg(feature = "objects")]
static mut OBJECT_CALLBACK_HANDLE: PVOID = core::ptr::null_mut();

#[cfg(feature = "ai_agent")]
static mut AGENT_EVENT: KEVENT = unsafe { core::mem::zeroed() };

// --- Optimized Logging Engine ---

unsafe fn log_event(event_type: u32, pid: HANDLE, p_pid: HANDLE, path: *const WCHAR, path_bytes: u16, score: u32) {
    let mut irql: KIRQL = 0;

    // Short critical section for slot reservation only
    KeAcquireSpinLock(&mut QUEUE_LOCK, &mut irql);

    let tail = QUEUE_TAIL.load(Ordering::Relaxed);
    let head = QUEUE_HEAD.load(Ordering::Relaxed);

    if (tail + 1) % MAX_EVENTS != head {
        let ev = &mut EVENT_QUEUE[tail];
        ev.event_type = event_type;
        ev.pid = pid;
        ev.parent_pid = p_pid;
        ev.timestamp = KeQueryPerformanceCounter(core::ptr::null_mut());
        ev.anomaly_score_fixed = score;

        // Zero-allocation copy
        if !path.is_null() && path_bytes > 0 {
            let len = (path_bytes / 2).min(260);
            ev.path_len = len;
            RtlCopyMemory(ev.path.as_mut_ptr() as _, path as _, (len * 2) as usize);
        } else { ev.path_len = 0; }

        QUEUE_TAIL.store((tail + 1) % MAX_EVENTS, Ordering::Release);

        #[cfg(feature = "ai_agent")]
        KeSetEvent(&mut AGENT_EVENT, IO_NO_INCREMENT as i32, FALSE as u8);
    }
    KeReleaseSpinLock(&mut QUEUE_LOCK, irql);
}

// --- Advanced Detection Callbacks ---

// 1. Process Monitoring (Hollowing Detection)
unsafe extern "system" fn process_notify_callback(_: PEPROCESS, pid: HANDLE, info: *mut PS_CREATE_NOTIFY_INFO) {
    if !info.is_null() {
        // Detect Process Hollowing: Process created in SUSPENDED state (Bit 0 of Flags)
        let is_suspended = ((*info).Flags & 0x1) != 0;
        let score = if is_suspended { 600 } else { 0 };

        let (buf, len) = if !(*info).ImageFileName.is_null() {
            ((*(*info).ImageFileName).Buffer, (*(*info).ImageFileName).Length)
        } else { (core::ptr::null(), 0) };

        log_event(0, pid, (*info).ParentProcessId, buf, len, score);
    }
}

// 2. Thread Monitoring (Injection Detection)
#[cfg(feature = "threads")]
unsafe extern "system" fn thread_notify_callback(pid: HANDLE, tid: HANDLE, create: u8) {
    if create != 0 {
        let current_pid = PsGetCurrentProcessId();
        // Detect Injection: Current Process creating thread in Remote Process
        let score = if current_pid != pid { 900 } else { 0 };
        log_event(7, pid, tid, core::ptr::null(), 0, score);
    }
}

// 3. Minifilter (Performance Optimization: Stream Contexts)
unsafe extern "system" fn pre_operation_callback(data: *mut FLT_CALLBACK_DATA, obj: PFLT_RELATED_OBJECTS, _: *mut PVOID) -> FLT_PREOP_CALLBACK_STATUS {
    let op = (*(*data).Iopb).MajorFunction as u32;
    let mut ctx: *mut MonitorStreamContext = core::ptr::null_mut();

    // Fast Path: Check if we already know this file's name from the Context
    if NT_SUCCESS(FltGetStreamContext((*obj).Instance, (*obj).FileObject, &mut ctx as *mut _ as *mut PFLT_CONTEXT)) {
        log_event(op, PsGetCurrentProcessId(), core::ptr::null_mut(), (*ctx).name.as_ptr(), (*ctx).name_len * 2, 0);
        FltReleaseContext(ctx as PFLT_CONTEXT);
    } else if op == IRP_MJ_CREATE {
        // Slow Path: File Open. Resolve name and cache it.
        let mut name_info: *mut FLT_FILE_NAME_INFORMATION = core::ptr::null_mut();
        if NT_SUCCESS(FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &mut name_info)) {
            FltParseFileNameInformation(name_info);
            log_event(op, PsGetCurrentProcessId(), core::ptr::null_mut(), (*name_info).Name.Buffer, (*name_info).Name.Length, 0);

            // Allocate Context
            if NT_SUCCESS(FltAllocateContext(FILTER_HANDLE, FLT_STREAM_CONTEXT, core::mem::size_of::<MonitorStreamContext>() as u64, NonPagedPoolNx, &mut ctx as *mut _ as *mut PFLT_CONTEXT)) {
                let len = ((*name_info).Name.Length / 2).min(260);
                (*ctx).name_len = len;
                RtlCopyMemory((*ctx).name.as_mut_ptr() as _, (*name_info).Name.Buffer as _, (len * 2) as usize);

                // Attach Context
                FltSetStreamContext((*obj).Instance, (*obj).FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx as PFLT_CONTEXT, core::ptr::null_mut());
                FltReleaseContext(ctx as PFLT_CONTEXT);
            }
            FltReleaseFileNameInformation(name_info);
        }
    }
    FLT_PREOP_SUCCESS_NO_CALLBACK
}

// 4. Object Callback (Suspicious Handle Detection)
#[cfg(feature = "objects")]
unsafe extern "system" fn object_callback(_: PVOID, pre_info: *mut OB_PRE_OPERATION_INFORMATION) -> OB_PREOP_CALLBACK_STATUS {
    if (*pre_info).ObjectType == *PsProcessType {
        let access = (*(*pre_info).Parameters).CreateHandleInformation.DesiredAccess;

        // VM_WRITE (0x0020) | VM_OPERATION (0x0008) often used for injection
        const SUSPICIOUS_MASK: u32 = 0x0028;

        if (access & SUSPICIOUS_MASK) == SUSPICIOUS_MASK {
            // Check if targeting self or other
            if PsGetCurrentProcessId() != PsGetProcessId((*pre_info).Object as PEPROCESS) {
                 log_event(8, PsGetCurrentProcessId(), core::ptr::null_mut(), core::ptr::null(), 0, 850);
            }
        }
    }
    OB_PREOP_SUCCESS
}

// --- IOCTL & Lifecycle ---

unsafe extern "system" fn ioctl_handler(_: PDEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    let stack = IoGetCurrentIrpStackLocation(irp);
    if (*stack).Parameters.DeviceIoControl.IoControlCode == 0x80002004 {
        let mut irql: KIRQL = 0;
        KeAcquireSpinLock(&mut QUEUE_LOCK, &mut irql);

        let head = QUEUE_HEAD.load(Ordering::Acquire);
        let tail = QUEUE_TAIL.load(Ordering::Acquire);
        let out_buf = (*irp).AssociatedIrp.SystemBuffer;
        let out_len = (*stack).Parameters.DeviceIoControl.OutputBufferLength as usize;
        let ev_size = core::mem::size_of::<MonitorEvent>();

        // Calculate available items (handling wrap-around conceptually)
        let mut count = if tail >= head { tail - head } else { MAX_EVENTS - head + tail };
        count = core::cmp::min(count, out_len / ev_size);

        if count > 0 {
            // Split-Copy Logic
            let chunk1 = core::cmp::min(count, MAX_EVENTS - head);
            RtlCopyMemory(out_buf, &EVENT_QUEUE[head] as *const _ as _, chunk1 * ev_size);

            if chunk1 < count {
                let dest = (out_buf as usize + (chunk1 * ev_size)) as *mut c_void;
                RtlCopyMemory(dest, &EVENT_QUEUE[0] as *const _ as _, (count - chunk1) * ev_size);
            }

            QUEUE_HEAD.store((head + count) % MAX_EVENTS, Ordering::Release);
            (*irp).IoStatus.Information = (count * ev_size) as ULONG_PTR;
            (*irp).IoStatus.Status = STATUS_SUCCESS;
        } else {
            (*irp).IoStatus.Status = STATUS_NO_MORE_ENTRIES;
        }
        KeReleaseSpinLock(&mut QUEUE_LOCK, irql);
    }
    let status = (*irp).IoStatus.Status;
    IoCompleteRequest(irp, IO_NO_INCREMENT as i8);
    status
}

#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(driver: PDRIVER_OBJECT, _: PCUNICODE_STRING) -> NTSTATUS {
    KeInitializeSpinLock(&mut QUEUE_LOCK);
    #[cfg(feature = "ai_agent")]
    KeInitializeEvent(&mut AGENT_EVENT, NotificationEvent, FALSE as u8);

    // Register Callbacks
    PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), FALSE as u8);

    #[cfg(feature = "threads")]
    PsSetCreateThreadNotifyRoutine(Some(thread_notify_callback));

    #[cfg(feature = "objects")]
    {
        // Must allow dynamic registration for OB callbacks
        let mut op_reg = OB_OPERATION_REGISTRATION {
            ObjectType: PsProcessType,
            Operations: OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            PreOperation: Some(object_callback),
            PostOperation: None
        };
        let mut cb_reg = OB_CALLBACK_REGISTRATION {
            Version: OB_FLT_REGISTRATION_VERSION as u16,
            OperationRegistrationCount: 1,
            RegistrationContext: core::ptr::null_mut(),
            Altitude: RtlInitUnicodeString("320000"),
            OperationRegistration: &mut op_reg
        };
        ObRegisterCallbacks(&cb_reg, &mut OBJECT_CALLBACK_HANDLE);
    }

    // Minifilter
    let mut reg: FLT_REGISTRATION = core::mem::zeroed();
    reg.Size = core::mem::size_of::<FLT_REGISTRATION>() as USHORT;
    reg.Version = FLT_REGISTRATION_VERSION as USHORT;
    reg.OperationRegistration = OP_REG.as_ptr();
    reg.ContextRegistration = CONTEXT_REG.as_ptr();

    if NT_SUCCESS(FltRegisterFilter(driver, &reg, &mut FILTER_HANDLE)) {
        FltStartFiltering(FILTER_HANDLE);
    }

    // Device
    let mut dev_name = RtlInitUnicodeString(r"\Device\EndpointMonitor\0");
    let mut device: PDEVICE_OBJECT = core::ptr::null_mut();
    if NT_SUCCESS(IoCreateDevice(driver, 0, &mut dev_name, FILE_DEVICE_UNKNOWN, 0, FALSE as u8, &mut device)) {
        (*driver).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(ioctl_handler);
        (*driver).DriverUnload = Some(driver_unload);
    }
    STATUS_SUCCESS
}

pub unsafe extern "system" fn driver_unload(driver: PDRIVER_OBJECT) {
    PsSetCreateProcessNotifyRoutineEx(Some(process_notify_callback), TRUE as u8);
    #[cfg(feature = "threads")]
    PsRemoveCreateThreadNotifyRoutine(Some(thread_notify_callback));
    #[cfg(feature = "objects")]
    if !OBJECT_CALLBACK_HANDLE.is_null() { ObUnRegisterCallbacks(OBJECT_CALLBACK_HANDLE); }
    FltUnregisterFilter(FILTER_HANDLE);
    IoDeleteDevice((*driver).DeviceObject);
}

// Configs
static OP_REG: [FLT_OPERATION_REGISTRATION; 4] = [
    FLT_OPERATION_REGISTRATION { MajorFunction: IRP_MJ_CREATE, Flags: 0, PreOperation: Some(pre_operation_callback), PostOperation: None, Reserved1: 0 },
    FLT_OPERATION_REGISTRATION { MajorFunction: IRP_MJ_READ, Flags: 0, PreOperation: Some(pre_operation_callback), PostOperation: None, Reserved1: 0 },
    FLT_OPERATION_REGISTRATION { MajorFunction: IRP_MJ_WRITE, Flags: 0, PreOperation: Some(pre_operation_callback), PostOperation: None, Reserved1: 0 },
    FLT_OPERATION_REGISTRATION { MajorFunction: IRP_MJ_OPERATION_END, Flags: 0, PreOperation: None, PostOperation: None, Reserved1: 0 },
];
static CONTEXT_REG: [FLT_CONTEXT_REGISTRATION; 2] = [
    FLT_CONTEXT_REGISTRATION { ContextType: FLT_STREAM_CONTEXT, Flags: 0, ContextCleanupCallback: None, Size: 600, PoolTag: TAG_CONTEXT },
    FLT_CONTEXT_REGISTRATION { ContextType: FLT_CONTEXT_END, ..unsafe { core::mem::zeroed() } }
];
fn RtlInitUnicodeString(s: &str) -> UNICODE_STRING {
    let mut us = UNICODE_STRING::default();
    us.Length = (s.len() * 2) as u16; us.MaximumLength = us.Length + 2;
    us.Buffer = s.as_ptr() as *mut u16; us
}