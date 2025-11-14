// SPDX-License-Identifier: MIT OR Apache-2.0

//! StorageSecurityCommand protocol.

#[cfg(doc)]
use crate::Status;
use crate::proto::unsafe_protocol;
use crate::{Result, StatusExt};
use uefi_raw::protocol::media::StorageSecurityCommandProtocol;

/// Storage Security Command [`Protocol`].
///
/// Used to abstract sending and receiving security protocol commands to
/// storage devices.
///
/// # UEFI Spec Description
/// This protocol is used to abstract mass storage devices to allow code
/// running in the EFI boot services environment to send security protocol
/// commands to mass storage devices without specific knowledge of the type
/// of device or controller that manages the device. Functions are defined
/// to send or retrieve security protocol defined data to and from mass
/// storage devices. This protocol shall be supported on all physical and
/// logical storage devices supporting the EFI_BLOCK_IO_PROTOCOL or
/// EFI_BLOCK_IO2_PROTOCOL in the EFI boot services environment and one of
/// the following command sets (or their alternative) at the bus level:
///
/// * TRUSTED SEND/RECEIVE commands of the ATA8-ACS command set or its successor
/// * SECURITY PROTOCOL IN/OUT commands of the SPC-4 command set or its successor.
///
/// If the mass storage device is part of a RAID set, the specific physical device
/// may not support the block IO protocols directly, but they are supported by
/// the logical device defining the RAID set. In this case the MediaId parameter
/// may not be available and its value is undefined for this interface.
///
/// [`Protocol`]: uefi::proto::Protocol
#[derive(Debug)]
#[repr(transparent)]
#[unsafe_protocol(StorageSecurityCommandProtocol::GUID)]
pub struct StorageSecurityCommand(StorageSecurityCommandProtocol);

impl StorageSecurityCommand {
    /// Receive data and/or the result of one or more commands sent by `send_data()`.
    ///
    /// # Errors
    ///
    /// See section `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL.ReceiveData()` in the UEFI Specification
    /// for details.
    ///
    /// * [`Status::BUFFER_TOO_SMALL`]
    /// * [`Status::UNSUPPORTED`]
    /// * [`Status::DEVICE_ERROR`]
    /// * [`Status::NO_MEDIA`]
    /// * [`Status::MEDIA_CHANGED`]
    /// * [`Status::INVALID_PARAMETER`]
    /// * [`Status::TIMEOUT`]
    pub fn receive_data<'a>(
        &mut self,
        media_id: u32,
        timeout: u64,
        protocol: u8,
        protocol_specific: u16,
        data: &'a mut [u8],
    ) -> Result<&'a [u8]> {
        let mut actual_size: usize = 0;

        unsafe {
            (self.0.receive_data)(
                &mut self.0,
                media_id,
                timeout,
                protocol,
                protocol_specific,
                data.len(),
                data.as_mut_ptr().cast(),
                &mut actual_size,
            )
        }
        .to_result_with_val(|| &data[..actual_size])
    }

    /// Send a security protocol command to a device.
    ///
    /// # Errors
    ///
    /// See section `EFI_STORAGE_SECURITY_COMMAND_PROTOCOL.SendData()` in the UEFI Specification
    /// for details.
    ///
    /// * [`Status::UNSUPPORTED`]
    /// * [`Status::DEVICE_ERROR`]
    /// * [`Status::NO_MEDIA`]
    /// * [`Status::MEDIA_CHANGED`]
    /// * [`Status::INVALID_PARAMETER`]
    /// * [`Status::TIMEOUT`]
    pub fn send_data(
        &mut self,
        media_id: u32,
        timeout: u64,
        protocol: u8,
        protocol_specific: u16,
        data: &[u8],
    ) -> Result {
        unsafe {
            (self.0.send_data)(
                &mut self.0,
                media_id,
                timeout,
                protocol,
                protocol_specific,
                data.len(),
                data.as_ptr().cast(),
            )
        }
        .to_result()
    }
}
