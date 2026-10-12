//! Best-effort process hardening for secrets held in memory.
//!
//! * [`harden_process`] disables core dumps so a crash cannot spill secrets to
//!   disk, and (on Linux) marks the process non-dumpable.
//! * [`lock_region`] / [`unlock_region`] pin a memory range with `mlock` so it
//!   is never written to swap.
//!
//! All functions are best-effort: failures are reported as booleans and never
//! propagate as errors, because security should not be weaker on platforms that
//! lack a given primitive.

/// Disable core dumps (and, on Linux, make the process non-dumpable).
///
/// Call once at startup. Returns `true` when the core-dump limit was raised.
pub fn harden_process() -> bool {
    #[cfg(unix)]
    {
        // RLIMIT_CORE = 4 on Linux, 4 on macOS.
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let ok = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0;
        #[cfg(target_os = "linux")]
        {
            unsafe {
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            }
        }
        ok
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Pin `len` bytes at `ptr` in RAM (never swapped). Best-effort: returns
/// `false` when the platform or the resource limit refuses.
///
/// # Safety
/// `ptr` must point to at least `len` valid bytes owned by the caller.
pub unsafe fn lock_region(ptr: *const u8, len: usize) -> bool {
    if ptr.is_null() || len == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        libc::mlock(ptr as *const libc::c_void, len) == 0
    }
    #[cfg(not(unix))]
    {
        let _ = (ptr, len);
        false
    }
}

/// Undo [`lock_region`]. Best-effort.
///
/// # Safety
/// `ptr`/`len` must match a previous successful [`lock_region`] call.
pub unsafe fn unlock_region(ptr: *const u8, len: usize) -> bool {
    if ptr.is_null() || len == 0 {
        return false;
    }
    #[cfg(unix)]
    {
        libc::munlock(ptr as *const libc::c_void, len) == 0
    }
    #[cfg(not(unix))]
    {
        let _ = (ptr, len);
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_process_is_best_effort_and_does_not_panic() {
        // On macOS/Linux this should succeed; elsewhere it returns false.
        let _ = harden_process();
    }

    #[test]
    fn lock_and_unlock_a_heap_buffer() {
        let buf = [0u8; 64];
        let locked = unsafe { lock_region(buf.as_ptr(), buf.len()) };
        // Whether locking succeeds depends on the platform; either way we must
        // be able to unlock a valid range without panicking.
        assert!(unsafe { unlock_region(buf.as_ptr(), buf.len()) } || !locked);
    }

    #[test]
    fn null_and_empty_are_rejected() {
        assert!(!unsafe { lock_region(std::ptr::null(), 8) });
        assert!(!unsafe { unlock_region(std::ptr::null(), 8) });
        let buf = [0u8; 4];
        assert!(!unsafe { lock_region(buf.as_ptr(), 0) });
    }
}
