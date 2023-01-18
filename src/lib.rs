use std::{
    ffi::c_void,
    mem::{size_of_val, transmute},
    sync::Mutex,
};

use once_cell::sync::Lazy;
use windows::{
    core::{HSTRING, PCWSTR, PWSTR},
    s,
    Win32::{
        Foundation::{BOOL, FARPROC, HINSTANCE, MAX_PATH},
        Networking::WinHttp::{
            WINHTTP_ACCESS_TYPE, WINHTTP_FLAG_SECURE, WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
            WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3, WINHTTP_OPEN_REQUEST_FLAGS,
            WINHTTP_OPTION_SECURE_PROTOCOLS,
        },
        System::{
            LibraryLoader::{GetProcAddress, LoadLibraryW},
            SystemInformation::GetSystemDirectoryW,
            SystemServices::DLL_PROCESS_ATTACH,
        },
    },
};

static mut ORIGINAL_WIN_HTTP_ADD_REQUEST_HEADERS: FARPROC = None;
static mut ORIGINAL_WIN_HTTP_CLOSE_HANDLE: FARPROC = None;
static mut ORIGINAL_WIN_HTTP_CONNECT: FARPROC = None;
static mut ORIGINAL_WIN_HTTP_OPEN: FARPROC = None;
static mut ORIGINAL_WIN_HTTP_OPEN_REQUEST: FARPROC = None;
static mut ORIGINAL_WIN_HTTP_QUERY_DATA_AVAILABLE: FARPROC = None;
static mut ORIGINAL_WIN_HTTP_QUERY_HEADERS: FARPROC = None;
static mut ORIGINAL_WIN_HTTP_READ_DATA: FARPROC = None;
static mut ORIGINAL_WIN_HTTP_RECEIVE_RESPONSE: FARPROC = None;
static mut ORIGINAL_WIN_HTTP_SEND_REQUEST: FARPROC = None;
static mut ORIGINAL_WIN_HTTP_SET_OPTION: FARPROC = None;
static mut ORIGINAL_WIN_HTTP_SET_TIMEOUTS: FARPROC = None;

static P_AT_CONN: Lazy<Mutex<Option<usize>>> = Lazy::new(Default::default);

#[no_mangle]
pub extern "system" fn WinHttpAddRequestHeaders(
    hrequest: *mut c_void,
    lpszheaders: PCWSTR,
    dwheaderslength: u32,
    dwmodifiers: u32,
) -> BOOL {
    type Func = extern "system" fn(
        hrequest: *mut c_void,
        lpszheaders: PCWSTR,
        dwheaderslength: u32,
        dwmodifiers: u32,
    ) -> BOOL;
    let func: Func = unsafe { transmute(ORIGINAL_WIN_HTTP_ADD_REQUEST_HEADERS) };
    func(hrequest, lpszheaders, dwheaderslength, dwmodifiers)
}

#[no_mangle]
pub extern "system" fn WinHttpCloseHandle(hinternet: *mut c_void) -> BOOL {
    type Func = extern "system" fn(hinternet: *mut c_void) -> BOOL;
    let func: Func = unsafe { transmute(ORIGINAL_WIN_HTTP_CLOSE_HANDLE) };
    func(hinternet)
}

#[no_mangle]
pub extern "system" fn WinHttpConnect(
    session: *mut c_void,
    server_name: PCWSTR,
    mut server_port: u32,
    reserved: u32,
) -> *mut c_void {
    let p_at_patch = server_name == PCWSTR(HSTRING::from("p-at.net").as_ptr())
        && [80, 443].contains(&server_port);
    if p_at_patch {
        server_port = 443;
    }

    type Func = extern "system" fn(
        hsession: *mut c_void,
        pswzservername: PCWSTR,
        nserverport: u32,
        dwreserved: u32,
    ) -> *mut c_void;
    let func: Func = unsafe { transmute(ORIGINAL_WIN_HTTP_CONNECT) };
    let result = func(session, server_name, server_port, reserved);

    if p_at_patch && !result.is_null() {
        *P_AT_CONN.lock().unwrap() = Some(result as usize);
    }
    result
}

#[no_mangle]
pub extern "system" fn WinHttpOpen(
    pszagentw: PCWSTR,
    dwaccesstype: WINHTTP_ACCESS_TYPE,
    pszproxyw: PCWSTR,
    pszproxybypassw: PCWSTR,
    dwflags: u32,
) -> *mut c_void {
    type Func = extern "system" fn(
        pszagentw: PCWSTR,
        dwaccesstype: WINHTTP_ACCESS_TYPE,
        pszproxyw: PCWSTR,
        pszproxybypassw: PCWSTR,
        dwflags: u32,
    ) -> *mut c_void;
    let func: Func = unsafe { transmute(ORIGINAL_WIN_HTTP_OPEN) };
    let internet = func(pszagentw, dwaccesstype, pszproxyw, pszproxybypassw, dwflags);

    {
        let flag = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;

        type Func = extern "system" fn(
            hinternet: *const c_void,
            dwoption: u32,
            lpbuffer: *const c_void,
            dwbufferlength: u32,
        ) -> BOOL;
        let func: Func = unsafe { transmute(ORIGINAL_WIN_HTTP_SET_OPTION) };
        func(
            internet,
            WINHTTP_OPTION_SECURE_PROTOCOLS,
            &flag as *const _ as _,
            size_of_val(&flag) as u32,
        )
        .ok()
        .unwrap();
    }
    internet
}

#[no_mangle]
pub extern "system" fn WinHttpOpenRequest(
    connect: *mut c_void,
    verb: PCWSTR,
    object_name: PCWSTR,
    version: PCWSTR,
    referrer: PCWSTR,
    accept_types: *mut PWSTR,
    mut dwflags: WINHTTP_OPEN_REQUEST_FLAGS,
) -> *mut c_void {
    if Some(connect as usize) == *P_AT_CONN.lock().unwrap()
        && dwflags == WINHTTP_OPEN_REQUEST_FLAGS(0)
    {
        dwflags = WINHTTP_FLAG_SECURE;
    }

    type Func = extern "system" fn(
        hconnect: *mut c_void,
        pwszverb: PCWSTR,
        pwszobjectname: PCWSTR,
        pwszversion: PCWSTR,
        pwszreferrer: PCWSTR,
        ppwszaccepttypes: *mut PWSTR,
        dwflags: WINHTTP_OPEN_REQUEST_FLAGS,
    ) -> *mut c_void;
    let func: Func = unsafe { transmute(ORIGINAL_WIN_HTTP_OPEN_REQUEST) };
    func(
        connect,
        verb,
        object_name,
        version,
        referrer,
        accept_types,
        dwflags,
    )
}

#[no_mangle]
pub extern "system" fn WinHttpQueryDataAvailable(
    hrequest: *mut c_void,
    lpdwnumberofbytesavailable: *mut u32,
) -> BOOL {
    type Func =
        extern "system" fn(hrequest: *mut c_void, lpdwnumberofbytesavailable: *mut u32) -> BOOL;
    let func: Func = unsafe { transmute(ORIGINAL_WIN_HTTP_QUERY_DATA_AVAILABLE) };
    func(hrequest, lpdwnumberofbytesavailable)
}

#[no_mangle]
pub extern "system" fn WinHttpQueryHeaders(
    hrequest: *mut c_void,
    dwinfolevel: u32,
    pwszname: PCWSTR,
    lpbuffer: *mut c_void,
    lpdwbufferlength: *mut u32,
    lpdwindex: *mut u32,
) -> BOOL {
    type Func = extern "system" fn(
        hrequest: *mut c_void,
        dwinfolevel: u32,
        pwszname: PCWSTR,
        lpbuffer: *mut c_void,
        lpdwbufferlength: *mut u32,
        lpdwindex: *mut u32,
    ) -> BOOL;
    let func: Func = unsafe { transmute(ORIGINAL_WIN_HTTP_QUERY_HEADERS) };
    func(
        hrequest,
        dwinfolevel,
        pwszname,
        lpbuffer,
        lpdwbufferlength,
        lpdwindex,
    )
}

#[no_mangle]
pub extern "system" fn WinHttpReadData(
    hrequest: *mut c_void,
    lpbuffer: *mut c_void,
    dwnumberofbytestoread: u32,
    lpdwnumberofbytesread: *mut u32,
) -> BOOL {
    type Func = extern "system" fn(
        hrequest: *mut c_void,
        lpbuffer: *mut c_void,
        dwnumberofbytestoread: u32,
        lpdwnumberofbytesread: *mut u32,
    ) -> BOOL;
    let func: Func = unsafe { transmute(ORIGINAL_WIN_HTTP_READ_DATA) };
    func(
        hrequest,
        lpbuffer,
        dwnumberofbytestoread,
        lpdwnumberofbytesread,
    )
}

#[no_mangle]
pub extern "system" fn WinHttpReceiveResponse(
    hrequest: *mut c_void,
    lpreserved: *mut c_void,
) -> BOOL {
    type Func = extern "system" fn(hrequest: *mut c_void, lpreserved: *mut c_void) -> BOOL;
    let func: Func = unsafe { transmute(ORIGINAL_WIN_HTTP_RECEIVE_RESPONSE) };
    func(hrequest, lpreserved)
}

#[no_mangle]
pub extern "system" fn WinHttpSendRequest(
    hrequest: *mut c_void,
    lpszheaders: PCWSTR,
    dwheaderslength: u32,
    lpoptional: *const c_void,
    dwoptionallength: u32,
    dwtotallength: u32,
    dwcontext: usize,
) -> BOOL {
    type Func = extern "system" fn(
        hrequest: *mut c_void,
        lpszheaders: PCWSTR,
        dwheaderslength: u32,
        lpoptional: *const c_void,
        dwoptionallength: u32,
        dwtotallength: u32,
        dwcontext: usize,
    ) -> BOOL;
    let func: Func = unsafe { transmute(ORIGINAL_WIN_HTTP_SEND_REQUEST) };
    func(
        hrequest,
        lpszheaders,
        dwheaderslength,
        lpoptional,
        dwoptionallength,
        dwtotallength,
        dwcontext,
    )
}

#[no_mangle]
pub extern "system" fn WinHttpSetTimeouts(
    hinternet: *mut c_void,
    nresolvetimeout: i32,
    nconnecttimeout: i32,
    nsendtimeout: i32,
    nreceivetimeout: i32,
) -> BOOL {
    type Func = extern "system" fn(
        hinternet: *mut c_void,
        nresolvetimeout: i32,
        nconnecttimeout: i32,
        nsendtimeout: i32,
        nreceivetimeout: i32,
    ) -> BOOL;
    let func: Func = unsafe { transmute(ORIGINAL_WIN_HTTP_SET_TIMEOUTS) };
    func(
        hinternet,
        nresolvetimeout,
        nconnecttimeout,
        nsendtimeout,
        nreceivetimeout,
    )
}

pub fn setup_winhttp_hook() {
    let system_directory = unsafe {
        let mut buf = [0u16; MAX_PATH as usize];
        GetSystemDirectoryW(Some(&mut buf));
        PCWSTR::from_raw(buf.as_ptr()).to_string().unwrap()
    };
    let dll_path = format!("{}\\winhttp.dll", system_directory);
    let dll_instance = unsafe { LoadLibraryW(PCWSTR(HSTRING::from(dll_path).as_ptr())) }.unwrap();

    if dll_instance.is_invalid() {
        panic!();
    }

    let func = unsafe { GetProcAddress(dll_instance, s!("WinHttpAddRequestHeaders")) };
    unsafe { ORIGINAL_WIN_HTTP_ADD_REQUEST_HEADERS = Some(func.unwrap()) };
    let func = unsafe { GetProcAddress(dll_instance, s!("WinHttpCloseHandle")) };
    unsafe { ORIGINAL_WIN_HTTP_CLOSE_HANDLE = Some(func.unwrap()) };
    let func = unsafe { GetProcAddress(dll_instance, s!("WinHttpConnect")) };
    unsafe { ORIGINAL_WIN_HTTP_CONNECT = Some(func.unwrap()) };
    let func = unsafe { GetProcAddress(dll_instance, s!("WinHttpOpen")) };
    unsafe { ORIGINAL_WIN_HTTP_OPEN = Some(func.unwrap()) };
    let func = unsafe { GetProcAddress(dll_instance, s!("WinHttpOpenRequest")) };
    unsafe { ORIGINAL_WIN_HTTP_OPEN_REQUEST = Some(func.unwrap()) };
    let func = unsafe { GetProcAddress(dll_instance, s!("WinHttpQueryDataAvailable")) };
    unsafe { ORIGINAL_WIN_HTTP_QUERY_DATA_AVAILABLE = Some(func.unwrap()) };
    let func = unsafe { GetProcAddress(dll_instance, s!("WinHttpQueryHeaders")) };
    unsafe { ORIGINAL_WIN_HTTP_QUERY_HEADERS = Some(func.unwrap()) };
    let func = unsafe { GetProcAddress(dll_instance, s!("WinHttpReadData")) };
    unsafe { ORIGINAL_WIN_HTTP_READ_DATA = Some(func.unwrap()) };
    let func = unsafe { GetProcAddress(dll_instance, s!("WinHttpReceiveResponse")) };
    unsafe { ORIGINAL_WIN_HTTP_RECEIVE_RESPONSE = Some(func.unwrap()) };
    let func = unsafe { GetProcAddress(dll_instance, s!("WinHttpSendRequest")) };
    unsafe { ORIGINAL_WIN_HTTP_SEND_REQUEST = Some(func.unwrap()) };
    let func = unsafe { GetProcAddress(dll_instance, s!("WinHttpSetOption")) };
    unsafe { ORIGINAL_WIN_HTTP_SET_OPTION = Some(func.unwrap()) };
    let func = unsafe { GetProcAddress(dll_instance, s!("WinHttpSetTimeouts")) };
    unsafe { ORIGINAL_WIN_HTTP_SET_TIMEOUTS = Some(func.unwrap()) };
}

#[no_mangle]
pub extern "system" fn DllMain(
    _inst_dll: HINSTANCE,
    reason: u32,
    _reserved: *const c_void,
) -> bool {
    if reason == DLL_PROCESS_ATTACH {
        setup_winhttp_hook();
    }
    true
}
