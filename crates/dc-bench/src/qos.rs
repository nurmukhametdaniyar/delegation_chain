//! QoS for measuring threads (SPEC §13.5, D-42). macOS on Apple Silicon has
//! no working thread-affinity API, so runs are not pinned. Instead every
//! measuring thread, in every arm, asks for the user-interactive QoS class,
//! which the scheduler places on performance cores.
//!
//! This is the one `unsafe` FFI call permitted in `dc-bench` (SPEC §0 rule
//! 9; `scripts/check-unsafe.sh`).
#![allow(unsafe_code)]

/// Sets the calling thread's QoS class to user-interactive. Returns whether
/// the call succeeded; the harness records it. Always `false` off macOS.
pub fn set_user_interactive() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `pthread_set_qos_class_self_np` takes a class and a relative
        // priority by value and affects only the calling thread. 0 is the
        // documented default relative priority.
        let rc = unsafe {
            libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0)
        };
        rc == 0
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}
