use anyhow::{anyhow, bail, Result};
use std::ffi::{c_char, c_void, CString};
use std::sync::Arc;

mod dynlib {
    use std::ffi::c_void;

    #[cfg(unix)]
    mod imp {
        use std::ffi::{c_char, c_int, c_void};

        const RTLD_NOW: c_int = 2;

        extern "C" {
            fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
            fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
            fn dlclose(handle: *mut c_void) -> c_int;
            fn dlerror() -> *mut c_char;
        }

        pub unsafe fn open(name: &str) -> Result<*mut c_void, String> {
            let name = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
            let handle = dlopen(name.as_ptr(), RTLD_NOW);
            if handle.is_null() {
                Err(last_error())
            } else {
                Ok(handle)
            }
        }

        pub unsafe fn symbol(handle: *mut c_void, name: &[u8]) -> Result<*mut c_void, String> {
            let symbol = dlsym(handle, name.as_ptr() as *const c_char);
            if symbol.is_null() {
                Err(last_error())
            } else {
                Ok(symbol)
            }
        }

        pub unsafe fn close(handle: *mut c_void) {
            dlclose(handle);
        }

        unsafe fn last_error() -> String {
            let error = dlerror();
            if error.is_null() {
                "неизвестная ошибка динамической загрузки".to_string()
            } else {
                std::ffi::CStr::from_ptr(error)
                    .to_string_lossy()
                    .into_owned()
            }
        }
    }

    #[cfg(windows)]
    mod imp {
        use std::ffi::c_void;

        extern "system" {
            fn LoadLibraryA(name: *const u8) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
            fn FreeLibrary(module: *mut c_void) -> i32;
        }

        pub unsafe fn open(name: &str) -> Result<*mut c_void, String> {
            let mut name = name.as_bytes().to_vec();
            name.push(0);
            let handle = LoadLibraryA(name.as_ptr());
            if handle.is_null() {
                Err(format!("LoadLibraryA: {}", name_display(&name)))
            } else {
                Ok(handle)
            }
        }

        pub unsafe fn symbol(handle: *mut c_void, name: &[u8]) -> Result<*mut c_void, String> {
            let symbol = GetProcAddress(handle, name.as_ptr());
            if symbol.is_null() {
                Err(format!("GetProcAddress: {}", name_display(name)))
            } else {
                Ok(symbol)
            }
        }

        pub unsafe fn close(handle: *mut c_void) {
            FreeLibrary(handle);
        }

        fn name_display(name: &[u8]) -> String {
            let name = name.strip_suffix(&[0]).unwrap_or(name);
            String::from_utf8_lossy(name).into_owned()
        }
    }

    pub struct Dl {
        handle: *mut c_void,
    }

    impl Dl {
        pub fn open(name: &str) -> anyhow::Result<Self> {
            unsafe { imp::open(name) }
                .map(|handle| Self { handle })
                .map_err(|e| anyhow::anyhow!(e))
        }

        pub unsafe fn symbol<T: Copy>(&self, name: &[u8]) -> anyhow::Result<T> {
            let symbol = imp::symbol(self.handle, name).map_err(|e| anyhow::anyhow!(e))?;
            Ok(std::mem::transmute_copy(&symbol))
        }
    }

    impl Drop for Dl {
        fn drop(&mut self) {
            unsafe { imp::close(self.handle) }
        }
    }

    unsafe impl Send for Dl {}
    unsafe impl Sync for Dl {}
}
type ScardContext = usize;
type ScardHandle = usize;
type Long = i32;
type Dword = u32;
#[repr(C)]
struct ScardIoRequest {
    protocol: Dword,
    pci_length: Dword,
}
type FnEstablish =
    unsafe extern "C" fn(Dword, *const c_void, *const c_void, *mut ScardContext) -> Long;
type FnRelease = unsafe extern "C" fn(ScardContext) -> Long;
type FnListReaders =
    unsafe extern "C" fn(ScardContext, *const c_char, *mut c_char, *mut Dword) -> Long;
type FnConnect = unsafe extern "C" fn(
    ScardContext,
    *const c_char,
    Dword,
    Dword,
    *mut ScardHandle,
    *mut Dword,
) -> Long;
type FnDisconnect = unsafe extern "C" fn(ScardHandle, Dword) -> Long;
type FnTransmit = unsafe extern "C" fn(
    ScardHandle,
    *const ScardIoRequest,
    *const u8,
    Dword,
    *mut ScardIoRequest,
    *mut u8,
    *mut Dword,
) -> Long;
const SCARD_SCOPE_USER: Dword = 0;
const SCARD_SHARE_SHARED: Dword = 2;
const SCARD_PROTOCOL_ANY: Dword = 3;
const SCARD_LEAVE_CARD: Dword = 0;
const SCARD_SUCCESS: Long = 0;
const SCARD_E_NO_READERS_AVAILABLE: Long = 0x8010_002E_u32 as Long;
fn scard_err(what: &str, rc: Long) -> anyhow::Error {
    anyhow!("{what}: SCard error 0x{:08x}", rc as u32)
}
pub struct Pcsc {
    _lib: dynlib::Dl,
    establish: FnEstablish,
    release: FnRelease,
    list_readers: FnListReaders,
    connect: FnConnect,
    disconnect: FnDisconnect,
    transmit: FnTransmit,
}
impl Pcsc {
    pub fn load() -> Result<Arc<Self>> {
        let candidates: &[&str] = if cfg!(target_os = "windows") {
            &["winscard.dll"]
        } else {
            &["libpcsclite.so.1", "libpcsclite.so"]
        };
        let mut lib = None;
        for name in candidates {
            if let Ok(candidate) = dynlib::Dl::open(name) {
                lib = Some(candidate);
                break;
            }
        }
        let lib = lib.ok_or_else(|| {
            anyhow!("не удалось загрузить библиотеку PC/SC (искали: {candidates:?})")
        })?;
        unsafe {
            let establish = lib.symbol::<FnEstablish>(b"SCardEstablishContext\0")?;
            let release = lib.symbol::<FnRelease>(b"SCardReleaseContext\0")?;
            let list_readers = lib.symbol::<FnListReaders>(b"SCardListReaders\0")?;
            let connect = lib.symbol::<FnConnect>(b"SCardConnect\0")?;
            let disconnect = lib.symbol::<FnDisconnect>(b"SCardDisconnect\0")?;
            let transmit = lib.symbol::<FnTransmit>(b"SCardTransmit\0")?;
            Ok(Arc::new(Self {
                _lib: lib,
                establish,
                release,
                list_readers,
                connect,
                disconnect,
                transmit,
            }))
        }
    }
    pub fn list_readers(&self) -> Result<Vec<String>> {
        let mut ctx: ScardContext = 0;
        let rc = unsafe {
            (self.establish)(
                SCARD_SCOPE_USER,
                std::ptr::null(),
                std::ptr::null(),
                &mut ctx,
            )
        };
        if rc != SCARD_SUCCESS {
            bail!(scard_err("SCardEstablishContext", rc));
        }
        let result = (|| -> Result<Vec<String>> {
            let mut len: Dword = 0;
            let rc = unsafe {
                (self.list_readers)(ctx, std::ptr::null(), std::ptr::null_mut(), &mut len)
            };
            if rc == SCARD_E_NO_READERS_AVAILABLE {
                return Ok(Vec::new());
            }
            if rc != SCARD_SUCCESS {
                bail!(scard_err("SCardListReaders", rc));
            }
            let mut buf = vec![0u8; len as usize];
            let rc = unsafe {
                (self.list_readers)(
                    ctx,
                    std::ptr::null(),
                    buf.as_mut_ptr() as *mut c_char,
                    &mut len,
                )
            };
            if rc != SCARD_SUCCESS {
                bail!(scard_err("SCardListReaders", rc));
            }
            let mut readers = Vec::new();
            for part in buf.split(|b| *b == 0) {
                if part.is_empty() {
                    continue;
                }
                readers.push(String::from_utf8_lossy(part).into_owned());
            }
            Ok(readers)
        })();
        unsafe { (self.release)(ctx) };
        result
    }
    pub fn connect(self: &Arc<Self>, reader: &str) -> Result<Card> {
        let mut ctx: ScardContext = 0;
        let rc = unsafe {
            (self.establish)(
                SCARD_SCOPE_USER,
                std::ptr::null(),
                std::ptr::null(),
                &mut ctx,
            )
        };
        if rc != SCARD_SUCCESS {
            bail!(scard_err("SCardEstablishContext", rc));
        }
        let creader = match CString::new(reader) {
            Ok(reader) => reader,
            Err(e) => {
                unsafe { (self.release)(ctx) };
                return Err(e.into());
            }
        };
        let mut handle: ScardHandle = 0;
        let mut proto: Dword = 0;
        let rc = unsafe {
            (self.connect)(
                ctx,
                creader.as_ptr(),
                SCARD_SHARE_SHARED,
                SCARD_PROTOCOL_ANY,
                &mut handle,
                &mut proto,
            )
        };
        if rc != SCARD_SUCCESS {
            unsafe { (self.release)(ctx) };
            bail!(scard_err("SCardConnect", rc));
        }
        Ok(Card {
            pcsc: Arc::clone(self),
            ctx,
            handle,
            protocol: proto,
        })
    }
}
pub struct Card {
    pcsc: Arc<Pcsc>,
    ctx: ScardContext,
    handle: ScardHandle,
    protocol: Dword,
}
impl Card {
    pub fn transmit(&self, apdu: &[u8]) -> Result<(Vec<u8>, u16)> {
        let pci_len = std::mem::size_of::<ScardIoRequest>() as Dword;
        let send_pci = ScardIoRequest {
            protocol: self.protocol,
            pci_length: pci_len,
        };
        let mut recv_pci = ScardIoRequest {
            protocol: self.protocol,
            pci_length: pci_len,
        };
        let mut recv = vec![0u8; 4096];
        let mut recv_len: Dword = recv.len() as Dword;
        let rc = unsafe {
            (self.pcsc.transmit)(
                self.handle,
                &send_pci,
                apdu.as_ptr(),
                apdu.len() as Dword,
                &mut recv_pci,
                recv.as_mut_ptr(),
                &mut recv_len,
            )
        };
        if rc != SCARD_SUCCESS {
            bail!(scard_err("SCardTransmit", rc));
        }
        recv.truncate(recv_len as usize);
        if recv.len() < 2 {
            bail!("короткий ответ APDU ({} байт)", recv.len());
        }
        let sw = ((recv[recv.len() - 2] as u16) << 8) | recv[recv.len() - 1] as u16;
        recv.truncate(recv.len() - 2);
        Ok((recv, sw))
    }
}
impl Drop for Card {
    fn drop(&mut self) {
        unsafe {
            (self.pcsc.disconnect)(self.handle, SCARD_LEAVE_CARD);
            (self.pcsc.release)(self.ctx);
        }
    }
}
