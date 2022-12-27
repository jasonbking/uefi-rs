//! Storage Security Command Protocol

use crate::proto::unsafe_protocol;
use crate::{Result, Status};

/// The storage security command protocol.
///
/// This protocol provides the ability to send security protocol
/// comands to mass storage devices.
#[repr(C)]
#[unsafe_protocol("c88b0b6d-0dfc-49a7-9cb4-49074b4c3a78")]
pub struct SecurityCommand {
    recv_data: extern "efiapi" fn(
        this: &SecurityCommand,
        media_id: u32,
        timeout: u64,
        security_protocol: u8,
        security_protocol_data: u16,
        len: usize,
        buffer: *mut u8,
        xfer_size: *mut usize,
    ) -> Status,
    send_data: extern "efiapi" fn(
        this: &SecurityCommand,
        media_id: u32,
        timeout: u64,
        security_protocol: u8,
        security_protocol_data: u16,
        len: usize,
        buffer: *const u8,
    ) -> Status,
}

impl SecurityCommand {
    /// Receive a security protocol command from a device. Returns the number of bytes received.
    ///
    /// # Arguments:
    /// * `media_id` - ID of the medium to send data to.
    /// * `timeout` - The timeout in 100ns units to use for the execution of the command. A value of `0` will cause the function to wait indefinitely.
    /// * `proto` - The value of the "Security Protocol" parameter of the security protocol command to be sent.
    /// * `proto_data` - The value of the "Security Protocol Specific" parameter of the security protocol command to be sent.
    /// * `buffer` - The buffer to receive the command.
    ///
    /// # Errors:
    /// * `uefi::status::WARN_BUFFER_TOO_SMALL  `buffer` is too msall to store the output from the security protocol command. The contents of `buffer` contains truncated data.
    /// * `uefi::status::UNSUPPORTED`           The given `media_id` does not support security protocol commands.
    /// * `uefi::status::DEVICE_ERROR`          The security protocol command completed with an error.
    /// * `uefi::status::NO_MEDIA`              There is no media in the device.
    /// * `uefi::status::MEDIA_CHANGED`         `media_id` is not for the current media.
    /// * `uefi::status::INVALID_PARAMETER`     The security protocol command buffer was invalid.
    /// * `uefi::status::TIMEOUT`               A timeout occurred while waiting for the security protocol command to execute.
    pub fn recv_data(
        &self,
        media_id: u32,
        timeout: u64,
        proto: u8,
        proto_data: u16,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let mut xfer_len: usize = 0;
        match (self.recv_data)(
            self,
            media_id,
            timeout,
            proto,
            proto_data,
            buffer.len(),
            buffer.as_mut_ptr(),
            &mut xfer_len,
        ) {
            Status::SUCCESS => Ok(xfer_len),
            other => Err(other.into()),
        }
    }

    /// Send a security protocol command to a device.
    ///
    /// # Arguments:
    /// * `media_id` - ID of the medium to send data to.
    /// * `timeout` - The timeout in 100ns units to use for the execution of the command. A value of `0` will cause the function to wait indefinitely.
    /// * `proto` - The value of the "Security Protocol" parameter of the security protocol command to be sent.
    /// * `proto_data` - The value of the "Security Protocol Specific" parameter of the security protocol command to be sent.
    /// * `buffer` - Pointer to a buffer containing the command to send.
    ///
    /// # Errors:
    /// * `uefi::status::UNSUPPORTED`       The given `media_id` does not support security protocol commands.
    /// * `uefi::status::DEVICE_ERROR`      The security protocol command completed with an error.
    /// * `uefi::status::NO_MEDIA`          There is no media in the device.
    /// * `uefi::status::MEDIA_CHANGED`     `media_id` is not for the current media.
    /// * `uefi::status::INVALID_PARAMETER` The security protocol command buffer was invalid.
    /// * `uefi::status::TIMEOUT`           A timeout occurred while waiting for the security protocol command to execute.
    pub fn send_data(
        &self,
        media_id: u32,
        timeout: u64,
        proto: u8,
        proto_data: u16,
        buffer: &[u8],
    ) -> Result {
        (self.send_data)(
            self,
            media_id,
            timeout,
            proto,
            proto_data,
            buffer.len(),
            buffer.as_ptr(),
        )
        .into()
    }
}
