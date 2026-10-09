use anyhow::{Result, anyhow, bail};
use std::ffi::{CString, c_char, c_long, c_ulong, c_void};
use std::rc::Rc;

mod dynlib {
    use std::ffi::c_void;

    #[cfg(unix)]
    mod imp {
        use std::ffi::{c_char, c_int, c_void};

        const RTLD_NOW: c_int = 2;

        unsafe extern "C" {
            fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
            fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
            fn dlclose(handle: *mut c_void) -> c_int;
            fn dlerror() -> *mut c_char;
        }

        pub unsafe fn open(name: &str) -> Result<*mut c_void, String> {
            let name = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
            let handle = unsafe { dlopen(name.as_ptr(), RTLD_NOW) };
            if handle.is_null() {
                Err(unsafe { last_error() })
            } else {
                Ok(handle)
            }
        }

        pub unsafe fn symbol(handle: *mut c_void, name: &[u8]) -> Result<*mut c_void, String> {
            let symbol = unsafe { dlsym(handle, name.as_ptr() as *const c_char) };
            if symbol.is_null() {
                Err(unsafe { last_error() })
            } else {
                Ok(symbol)
            }
        }

        pub unsafe fn close(handle: *mut c_void) {
            unsafe { dlclose(handle) };
        }

        unsafe fn last_error() -> String {
            let error = unsafe { dlerror() };
            if error.is_null() {
                "неизвестная ошибка динамической загрузки".to_string()
            } else {
                unsafe { std::ffi::CStr::from_ptr(error) }
                    .to_string_lossy()
                    .into_owned()
            }
        }
    }

    #[cfg(windows)]
    mod imp {
        use std::ffi::c_void;

        unsafe extern "system" {
            fn LoadLibraryA(name: *const u8) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
            fn FreeLibrary(module: *mut c_void) -> i32;
        }

        pub unsafe fn open(name: &str) -> Result<*mut c_void, String> {
            let mut name = name.as_bytes().to_vec();
            name.push(0);
            let handle = unsafe { LoadLibraryA(name.as_ptr()) };
            if handle.is_null() {
                Err(format!("LoadLibraryA: {}", name_display(&name)))
            } else {
                Ok(handle)
            }
        }

        pub unsafe fn symbol(handle: *mut c_void, name: &[u8]) -> Result<*mut c_void, String> {
            let symbol = unsafe { GetProcAddress(handle, name.as_ptr()) };
            if symbol.is_null() {
                Err(format!("GetProcAddress: {}", name_display(name)))
            } else {
                Ok(symbol)
            }
        }

        pub unsafe fn close(handle: *mut c_void) {
            unsafe { FreeLibrary(handle) };
        }

        fn name_display(name: &[u8]) -> String {
            let name = name.strip_suffix(&[0]).unwrap_or(name);
            String::from_utf8_lossy(name).into_owned()
        }
    }

    pub struct Library {
        handle: *mut c_void,
    }

    impl Library {
        pub fn open(name: &str) -> anyhow::Result<Self> {
            unsafe { imp::open(name) }
                .map(|handle| Self { handle })
                .map_err(|e| anyhow::anyhow!(e))
        }

        pub unsafe fn symbol<T: Copy>(&self, name: &[u8]) -> anyhow::Result<T> {
            const { assert!(std::mem::size_of::<T>() == std::mem::size_of::<*mut c_void>()) };
            let symbol =
                unsafe { imp::symbol(self.handle, name) }.map_err(|e| anyhow::anyhow!(e))?;
            Ok(unsafe { std::mem::transmute_copy(&symbol) })
        }
    }

    impl Drop for Library {
        fn drop(&mut self) {
            unsafe { imp::close(self.handle) }
        }
    }
}
type Long = c_long;
type Dword = c_ulong;
type ScardContext = usize;
type ScardHandle = usize;
#[repr(C)]
struct ScardIoRequest {
    protocol: Dword,
    pci_length: Dword,
}
type FnEstablish =
    unsafe extern "system" fn(Dword, *const c_void, *const c_void, *mut ScardContext) -> Long;
type FnRelease = unsafe extern "system" fn(ScardContext) -> Long;
type FnListReaders =
    unsafe extern "system" fn(ScardContext, *const c_char, *mut c_char, *mut Dword) -> Long;
type FnConnect = unsafe extern "system" fn(
    ScardContext,
    *const c_char,
    Dword,
    Dword,
    *mut ScardHandle,
    *mut Dword,
) -> Long;
type FnDisconnect = unsafe extern "system" fn(ScardHandle, Dword) -> Long;
type FnTransmit = unsafe extern "system" fn(
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
    _lib: dynlib::Library,
    establish: FnEstablish,
    release: FnRelease,
    list_readers: FnListReaders,
    connect: FnConnect,
    disconnect: FnDisconnect,
    transmit: FnTransmit,
}
impl Pcsc {
    pub fn load() -> Result<Rc<Self>> {
        let candidates: &[&str] = if cfg!(target_os = "windows") {
            &["winscard.dll"]
        } else {
            &["libpcsclite.so.1", "libpcsclite.so"]
        };
        let lib = candidates
            .iter()
            .find_map(|name| dynlib::Library::open(name).ok())
            .ok_or_else(|| {
                anyhow!("не удалось загрузить библиотеку PC/SC (искали: {candidates:?})")
            })?;
        let suffix: &[u8] = if cfg!(windows) { b"A\0" } else { b"\0" };
        let name = |base: &[u8]| [base, suffix].concat();
        unsafe {
            let establish = lib.symbol::<FnEstablish>(b"SCardEstablishContext\0")?;
            let release = lib.symbol::<FnRelease>(b"SCardReleaseContext\0")?;
            let list_readers = lib.symbol::<FnListReaders>(&name(b"SCardListReaders"))?;
            let connect = lib.symbol::<FnConnect>(&name(b"SCardConnect"))?;
            let disconnect = lib.symbol::<FnDisconnect>(b"SCardDisconnect\0")?;
            let transmit = lib.symbol::<FnTransmit>(b"SCardTransmit\0")?;
            Ok(Rc::new(Self {
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
    fn establish_context(&self) -> Result<ScardContext> {
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
        Ok(ctx)
    }
    pub fn list_readers(&self) -> Result<Vec<String>> {
        let ctx = self.establish_context()?;
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
            Ok(buf
                .split(|b| *b == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect())
        })();
        unsafe { (self.release)(ctx) };
        result
    }
    pub fn connect(self: &Rc<Self>, reader: &str) -> Result<Card> {
        let ctx = self.establish_context()?;
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
            pcsc: Rc::clone(self),
            ctx,
            handle,
            protocol: proto,
        })
    }
}
pub struct Card {
    pcsc: Rc<Pcsc>,
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

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn loads_windows_scard_exports() {
        Pcsc::load().expect("WinSCard exports must resolve on Windows");
    }
}

#[cfg(test)]
mod abi_tests {
    use super::*;

    #[test]
    fn scard_types_follow_platform_long_width() {
        assert_eq!(std::mem::size_of::<Long>(), std::mem::size_of::<c_long>());
        assert_eq!(std::mem::size_of::<Dword>(), std::mem::size_of::<c_ulong>());
        assert_eq!(
            std::mem::size_of::<ScardIoRequest>(),
            2 * std::mem::size_of::<c_ulong>()
        );
    }

    #[test]
    fn scard_handles_are_pointer_width() {
        assert_eq!(
            std::mem::size_of::<ScardContext>(),
            std::mem::size_of::<*mut c_void>()
        );
        assert_eq!(
            std::mem::size_of::<ScardHandle>(),
            std::mem::size_of::<*mut c_void>()
        );
    }
}
