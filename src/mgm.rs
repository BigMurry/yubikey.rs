//! Management Key (MGM) for authenticating to the YubiKey management applet

// Adapted from yubico-piv-tool:
// <https://github.com/Yubico/yubico-piv-tool/>
//
// Copyright (c) 2014-2016 Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//   * Redistributions in binary form must reproduce the above
//     copyright notice, this list of conditions and the following
//     disclaimer in the documentation and/or other materials provided
//     with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::{Error, Result};
use log::error;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit as AesKeyInit};
use aes::{Aes128, Aes192, Aes256};
use des::{
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit},
    TdesEde3,
};

#[cfg(feature = "untested")]
use {
    crate::{
        consts::{
            CB_BUF_MAX, TAG_ADMIN_FLAGS_1, TAG_ADMIN_SALT, TAG_AUTO_EJECT_TIMEOUT,
            TAG_CHALRESP_TIMEOUT, TAG_CONFIG_LOCK, TAG_DEVICE_FLAGS, TAG_FORM_FACTOR,
            TAG_NFC_ENABLED, TAG_NFC_SUPPORTED, TAG_PROTECTED_MGM, TAG_REBOOT, TAG_SERIAL,
            TAG_UNLOCK, TAG_USB_ENABLED, TAG_USB_SUPPORTED, TAG_VERSION,
        },
        metadata::{AdminData, ProtectedData},
        piv::{ManagementSlotId, SlotAlgorithmId},
        serialization::Tlv,
        transaction::Transaction,
        yubikey::YubiKey,
        Serial, Version,
    },
    bitflags::bitflags,
    pbkdf2::pbkdf2_hmac,
    sha1::Sha1,
};

/// YubiKey MGMT Applet Name
#[cfg(feature = "untested")]
pub(crate) const APPLET_NAME: &str = "YubiKey MGMT";

/// MGMT Applet ID.
///
/// <https://developers.yubico.com/PIV/Introduction/Admin_access.html>
#[cfg(feature = "untested")]
pub(crate) const APPLET_ID: &[u8] = &[0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17];

mod tdes;
pub(crate) use tdes::DES_LEN_3DES;
use tdes::DES_LEN_DES;

pub(crate) const ADMIN_FLAGS_1_PROTECTED_MGM: u8 = 0x02;
const AES_LEN_128: usize = 16;
const AES_LEN_192: usize = 24;
const AES_LEN_256: usize = 32;
const AES_BLOCK_SIZE: usize = 16;

#[cfg(feature = "untested")]
const CB_ADMIN_SALT: usize = 16;

/// Number of PBKDF2 iterations to use when deriving from a password
#[cfg(feature = "untested")]
const ITER_MGM_PBKDF2: u32 = 10000;

/// Management Key (MGM) key types (manual/derived/protected).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MgmType {
    /// Manual
    Manual = 0,

    /// Derived
    Derived = 1,

    /// Protected
    Protected = 2,
}

/// Management key algorithm identifiers
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MgmAlgorithmId {
    /// Triple DES (3DES) in EDE mode
    ThreeDes,

    /// Aes128
    Aes128,

    /// Aes192
    Aes192,

    /// Aes256
    Aes256,
}

impl TryFrom<u8> for MgmAlgorithmId {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x03 => Ok(MgmAlgorithmId::ThreeDes),
            0x08 => Ok(MgmAlgorithmId::Aes128),
            0x0A => Ok(MgmAlgorithmId::Aes192),
            0x0C => Ok(MgmAlgorithmId::Aes256),
            _ => Err(Error::AlgorithmError),
        }
    }
}

impl From<MgmAlgorithmId> for u8 {
    fn from(id: MgmAlgorithmId) -> u8 {
        match id {
            MgmAlgorithmId::ThreeDes => 0x03,
            MgmAlgorithmId::Aes128 => 0x08,
            MgmAlgorithmId::Aes192 => 0x0A,
            MgmAlgorithmId::Aes256 => 0x0C,
        }
    }
}

impl MgmAlgorithmId {
    /// Looks up the algorithm for the given Yubikey's current management key.
    #[cfg(feature = "untested")]
    pub(crate) fn query(txn: &Transaction<'_>) -> Result<Self> {
        match txn.get_metadata(crate::piv::SlotId::Management(ManagementSlotId::Management)) {
            Ok(metadata) => match metadata.algorithm {
                SlotAlgorithmId::Management(alg) => Ok(alg),
                // We specifically queried the management key slot; getting a known
                // non-management algorithm back from the Yubikey is invalid.
                _ => Err(Error::InvalidObject),
            },
            // Firmware versions without `GET METADATA` only support 3DES.
            Err(Error::NotSupported) => Ok(MgmAlgorithmId::ThreeDes),
            // `Error::AlgorithmError` only occurs when a new algorithm is encountered.
            Err(Error::AlgorithmError) => Err(Error::NotSupported),
            // Raise other errors as-is.
            Err(e) => Err(e),
        }
    }

    /// challenge length for different algo type
    pub fn challenge_len(&self) -> usize {
        match self {
            MgmAlgorithmId::ThreeDes => DES_LEN_DES,
            _ => AES_BLOCK_SIZE,
        }
    }

    /// algo type code
    pub fn ty_code(&self) -> u8 {
        (*self).into()
    }

    /// key length
    pub fn key_len(&self) -> usize {
        match self {
            MgmAlgorithmId::ThreeDes => DES_LEN_3DES,
            MgmAlgorithmId::Aes128 => AES_LEN_128,
            MgmAlgorithmId::Aes192 => AES_LEN_192,
            MgmAlgorithmId::Aes256 => AES_LEN_256,
        }
    }
}

/// Management Key (MGM).
///
/// This key is used to authenticate to the management applet running on
/// a YubiKey in order to perform administrative functions.
///
/// 3DES is deprecated, the default is AES192
/// Authentication Management Key Type
#[derive(Clone)]
pub enum MgmKey {
    /// 3 DES key type, the deprecated one
    TDES([u8; DES_LEN_3DES]),

    /// AES128 type
    AES128([u8; AES_LEN_128]),

    /// AES192 type
    AES192([u8; AES_LEN_192]),

    /// AES256 type
    AES256([u8; AES_LEN_256]),
}

impl MgmKey {
    /// key algo tag
    /// https://github.com/Yubico/yubikey-manager/blob/f3c37f690a2b184232ee88feb614bee6f5054526/yubikit/piv.py#L145
    pub fn algo(&self) -> MgmAlgorithmId {
        match self {
            MgmKey::TDES(_) => MgmAlgorithmId::ThreeDes,
            MgmKey::AES128(_) => MgmAlgorithmId::Aes128,
            MgmKey::AES192(_) => MgmAlgorithmId::Aes192,
            MgmKey::AES256(_) => MgmAlgorithmId::Aes256,
        }
    }

    /// from firmware 5.7 and above, default key is aes192 type
    pub fn default_aes() -> Self {
        MgmKey::AES192([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
        ])
    }

    /// Generate a random MGM key, type AES192
    pub fn generate() -> Self {
        let mut key_bytes = [0u8; AES_LEN_192];
        OsRng.fill_bytes(&mut key_bytes);
        Self::AES192(key_bytes)
    }

    /// Create an MGM key from byte slice.
    ///
    /// Returns an error if the slice is the wrong size or the key is weak.
    #[deprecated(note = "should use `from_bytes_typed` instead")]
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Ok(Self::TDES(bytes.as_ref().try_into()?))
    }

    /// Create an MGM key from key slice and key algo
    ///
    /// Returns an error if key slice is the wrong size
    pub fn from_bytes_typed(bytes: impl AsRef<[u8]>, algo: MgmAlgorithmId) -> Result<Self> {
        match algo {
            MgmAlgorithmId::ThreeDes => Ok(Self::TDES(bytes.as_ref().try_into()?)),
            MgmAlgorithmId::Aes128 => Ok(Self::AES128(bytes.as_ref().try_into()?)),
            MgmAlgorithmId::Aes192 => Ok(Self::AES192(bytes.as_ref().try_into()?)),
            MgmAlgorithmId::Aes256 => Ok(Self::AES256(bytes.as_ref().try_into()?)),
        }
    }

    /// Create an MGM key from the given byte array.
    ///
    /// Returns an error if the key is weak.
    pub fn new(key_bytes: Vec<u8>, algo: MgmAlgorithmId) -> Result<Self> {
        match algo {
            MgmAlgorithmId::ThreeDes => {
                let key: [u8; DES_LEN_3DES] = key_bytes.try_into().map_err(|_| Error::SizeError)?;
                if tdes::is_weak_key(&key) {
                    error!(
                        "blacklisting key '{:?}' since it's weak (with odd parity)",
                        &key
                    );

                    return Err(Error::KeyError);
                }
                Ok(Self::TDES(key))
            }
            MgmAlgorithmId::Aes128 => Ok(Self::AES128(
                key_bytes.try_into().map_err(|_| Error::SizeError)?,
            )),
            MgmAlgorithmId::Aes192 => Ok(Self::AES192(
                key_bytes.try_into().map_err(|_| Error::SizeError)?,
            )),
            MgmAlgorithmId::Aes256 => Ok(Self::AES256(
                key_bytes.try_into().map_err(|_| Error::SizeError)?,
            )),
        }
    }

    /// create empty mgm key by algo
    pub fn empty(algo: MgmAlgorithmId) -> Self {
        match algo {
            MgmAlgorithmId::ThreeDes => Self::TDES([0u8; DES_LEN_3DES]),
            MgmAlgorithmId::Aes128 => Self::AES128([0u8; AES_LEN_128]),
            MgmAlgorithmId::Aes192 => Self::AES192([0u8; AES_LEN_192]),
            MgmAlgorithmId::Aes256 => Self::AES256([0u8; AES_LEN_256]),
        }
    }

    /// Get derived management key (MGM)
    #[cfg(feature = "untested")]
    pub fn get_derived(yubikey: &mut YubiKey, pin: &[u8]) -> Result<Self> {
        let txn = yubikey.begin_transaction()?;

        // Check the key algorithm.
        let alg = MgmAlgorithmId::query(&txn)?;
        // if alg != MgmAlgorithmId::ThreeDes {
        //     return Err(Error::NotSupported);
        // }

        // recover management key
        let admin_data = AdminData::read(&txn)?;
        let salt = admin_data.get_item(TAG_ADMIN_SALT)?;

        if salt.len() != CB_ADMIN_SALT {
            error!(
                "derived MGM salt exists, but is incorrect size: {} (expected {})",
                salt.len(),
                CB_ADMIN_SALT
            );

            return Err(Error::GenericError);
        }

        let mut mgm_key = MgmKey::empty(alg);

        // let mut mgm = [0u8; DES_LEN_3DES];
        pbkdf2_hmac::<Sha1>(pin, salt, ITER_MGM_PBKDF2, mgm_key.as_mut());
        // MgmKey::from_bytes(mgm)
        Ok(mgm_key)
    }

    /// Get protected management key (MGM)
    #[cfg(feature = "untested")]
    pub fn get_protected(yubikey: &mut YubiKey) -> Result<Self> {
        let txn = yubikey.begin_transaction()?;

        // Check the key algorithm.
        let alg = MgmAlgorithmId::query(&txn)?;
        // if alg != MgmAlgorithmId::ThreeDes {
        //     return Err(Error::NotSupported);
        // }

        let protected_data = ProtectedData::read(&txn)
            .inspect_err(|e| error!("could not read protected data (err: {:?})", e))?;

        let item = protected_data
            .get_item(TAG_PROTECTED_MGM)
            .inspect_err(|e| error!("could not read protected MGM from metadata (err: {:?})", e))?;

        // if item.len() != DES_LEN_3DES {
        //     error!(
        //         "protected data contains MGM, but is the wrong size: {} (expected {})",
        //         item.len(),
        //         DES_LEN_3DES
        //     );

        //     return Err(Error::AuthenticationError);
        // }

        MgmKey::from_bytes_typed(item, alg)
    }

    /// Resets the management key for the given YubiKey to the default value.
    ///
    /// This will wipe any metadata related to derived and PIN-protected management keys.
    #[cfg(feature = "untested")]
    pub fn set_default(yubikey: &mut YubiKey) -> Result<()> {
        MgmKey::default().set_manual(yubikey, false)
    }

    /// Configures the given YubiKey to use this management key.
    ///
    /// The management key must be stored by the user, and provided when performing key
    /// management operations.
    ///
    /// This will wipe any metadata related to derived and PIN-protected management keys.
    #[cfg(feature = "untested")]
    pub fn set_manual(&self, yubikey: &mut YubiKey, require_touch: bool) -> Result<()> {
        let txn = yubikey.begin_transaction()?;

        txn.set_mgm_key(self, require_touch)
            // Log a warning, since the device mgm key is corrupt or we're in a state
            // where we can't set the mgm key.
            .inspect_err(|e| error!("could not set new derived mgm key, err = {}", e))?;

        // After this point, we've set the mgm key, so the function should succeed,
        // regardless of being able to set the metadata.

        if let Ok(mut admin_data) = AdminData::read(&txn) {
            // Clear the protected mgm key bit.
            if let Ok(item) = admin_data.get_item(TAG_ADMIN_FLAGS_1) {
                let mut flags_1 = [0u8; 1];
                if item.len() == flags_1.len() {
                    flags_1.copy_from_slice(item);
                    flags_1[0] &= !ADMIN_FLAGS_1_PROTECTED_MGM;

                    if let Err(e) = admin_data.set_item(TAG_ADMIN_FLAGS_1, &flags_1) {
                        error!("could not set admin flags item, err = {}", e);
                    }
                } else {
                    error!(
                        "admin data flags are an incorrect size: {} (expected {})",
                        item.len(),
                        flags_1.len()
                    );
                }
            }

            // Remove any existing salt for a derived mgm key.
            if let Err(e) = admin_data.set_item(TAG_ADMIN_SALT, &[]) {
                error!("could not unset derived mgm salt (err = {})", e)
            }

            if let Err(e) = admin_data.write(&txn) {
                error!("could not write admin data, err = {}", e);
            }
        }

        // Clear any prior mgm key from protected data.
        if let Ok(mut protected_data) = ProtectedData::read(&txn) {
            if let Err(e) = protected_data.set_item(TAG_PROTECTED_MGM, &[]) {
                error!("could not clear protected mgm item, err = {:?}", e);
            } else if let Err(e) = protected_data.write(&txn) {
                error!("could not write protected data, err = {:?}", e);
            }
        }

        Ok(())
    }

    /// Configures the given YubiKey to use this as a PIN-protected management key.
    ///
    /// This enables key management operations to be performed with access to the PIN.
    #[cfg(feature = "untested")]
    pub fn set_protected(&self, yubikey: &mut YubiKey) -> Result<()> {
        let txn = yubikey.begin_transaction()?;

        txn.set_mgm_key(self, false)
            // log a warning, since the device mgm key is corrupt or we're in
            // a state where we can't set the mgm key
            .inspect_err(|e| error!("could not set new derived mgm key, err = {}", e))?;

        // after this point, we've set the mgm key, so the function should
        // succeed, regardless of being able to set the metadata

        // Fetch the current protected data, or start a blank metadata blob.
        let mut protected_data = ProtectedData::read(&txn).unwrap_or_default();

        // Set the new mgm key in protected data.
        if let Err(e) = protected_data.set_item(TAG_PROTECTED_MGM, self.as_ref()) {
            error!("could not set protected mgm item, err = {:?}", e);
        } else {
            protected_data
                .write(&txn)
                .inspect_err(|e| error!("could not write protected data, err = {:?}", e))?;
        }

        // set the protected mgm flag in admin data

        let mut flags_1 = [0u8; 1];

        let mut admin_data = if let Ok(mut admin_data) = AdminData::read(&txn) {
            if let Ok(item) = admin_data.get_item(TAG_ADMIN_FLAGS_1) {
                if item.len() == flags_1.len() {
                    flags_1.copy_from_slice(item);
                } else {
                    error!(
                        "admin data flags are an incorrect size: {} (expected {})",
                        item.len(),
                        flags_1.len()
                    );
                }
            } else {
                // flags are not set
                error!("admin data exists, but flags are not present");
            }

            // remove any existing salt
            if let Err(e) = admin_data.set_item(TAG_ADMIN_SALT, &[]) {
                error!("could not unset derived mgm salt (err = {})", e)
            }

            admin_data
        } else {
            AdminData::default()
        };

        flags_1[0] |= ADMIN_FLAGS_1_PROTECTED_MGM;

        if let Err(e) = admin_data.set_item(TAG_ADMIN_FLAGS_1, &flags_1) {
            error!("could not set admin flags item, err = {}", e);
        } else if let Err(e) = admin_data.write(&txn) {
            error!("could not write admin data, err = {}", e);
        }

        Ok(())
    }

    /// Encrypt with mgm key
    pub(crate) fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::TDES(k) => {
                let output: [u8; DES_LEN_DES] = input.try_into().map_err(|_| Error::SizeError)?;
                TdesEde3::new(k.into()).encrypt_block(&mut output.into());
                Ok(output.to_vec())
            }
            Self::AES128(k) => {
                let output: [u8; AES_BLOCK_SIZE] =
                    input.try_into().map_err(|_| Error::SizeError)?;
                let mut output = GenericArray::from(output);
                let key = GenericArray::from(k.to_owned());
                let cipher = Aes128::new(&key);
                cipher.encrypt_block(&mut output);
                Ok(output.to_vec())
            }
            Self::AES192(k) => {
                let output: [u8; AES_BLOCK_SIZE] =
                    input.try_into().map_err(|_| Error::SizeError)?;
                let mut output = GenericArray::from(output);
                let key = GenericArray::from(k.to_owned());
                let cipher = Aes192::new(&key);
                cipher.encrypt_block(&mut output);
                Ok(output.to_vec())
            }
            Self::AES256(k) => {
                let output: [u8; AES_BLOCK_SIZE] =
                    input.try_into().map_err(|_| Error::SizeError)?;
                let mut output = GenericArray::from(output);
                let key = GenericArray::from(k.to_owned());
                let cipher = Aes256::new(&key);
                cipher.encrypt_block(&mut output);
                Ok(output.to_vec())
            }
        }
    }

    /// Decrypt with mgm key
    pub(crate) fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::TDES(k) => {
                let output: [u8; DES_LEN_DES] = input.try_into().map_err(|_| Error::SizeError)?;
                TdesEde3::new(k.into()).decrypt_block(&mut output.into());
                Ok(output.to_vec())
            }
            Self::AES128(k) => {
                let output: [u8; AES_BLOCK_SIZE] =
                    input.try_into().map_err(|_| Error::SizeError)?;
                let mut output = GenericArray::from(output);
                let key = GenericArray::from(k.to_owned());
                let cipher = Aes128::new(&key);
                cipher.decrypt_block(&mut output);
                Ok(output.to_vec())
            }
            Self::AES192(k) => {
                let output: [u8; AES_BLOCK_SIZE] =
                    input.try_into().map_err(|_| Error::SizeError)?;
                let mut output = GenericArray::from(output);
                let key = GenericArray::from(k.to_owned());
                let cipher = Aes192::new(&key);
                cipher.decrypt_block(&mut output);
                Ok(output.to_vec())
            }
            Self::AES256(k) => {
                let output: [u8; AES_BLOCK_SIZE] =
                    input.try_into().map_err(|_| Error::SizeError)?;
                let mut output = GenericArray::from(output);
                let key = GenericArray::from(k.to_owned());
                let cipher = Aes256::new(&key);
                cipher.decrypt_block(&mut output);
                Ok(output.to_vec())
            }
        }
    }
}

impl AsRef<[u8]> for MgmKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            MgmKey::TDES(k) => k.as_slice(),
            MgmKey::AES128(k) => k.as_slice(),
            MgmKey::AES192(k) => k.as_slice(),
            MgmKey::AES256(k) => k.as_slice(),
        }
    }
}

impl AsMut<[u8]> for MgmKey {
    fn as_mut(&mut self) -> &mut [u8] {
        match self {
            MgmKey::TDES(k) => k.as_mut(),
            MgmKey::AES128(k) => k.as_mut(),
            MgmKey::AES192(k) => k.as_mut(),
            MgmKey::AES256(k) => k.as_mut(),
        }
    }
}

/// Default MGM key configured on all YubiKeys
impl Default for MgmKey {
    fn default() -> Self {
        MgmKey::TDES([
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
        ])
    }
}

impl Drop for MgmKey {
    fn drop(&mut self) {
        match self {
            MgmKey::TDES(k) => k.zeroize(),
            MgmKey::AES128(k) => k.zeroize(),
            MgmKey::AES192(k) => k.zeroize(),
            MgmKey::AES256(k) => k.zeroize(),
        }
    }
}

/// Manager for the YubiKey
/// Allows to enable applications hosted on the YubiKey
#[cfg(feature = "untested")]
pub struct Manager {
    client: YubiKey,
}

#[cfg(feature = "untested")]
impl Manager {
    /// Open the manager applet on the YubiKey
    pub fn new(mut client: YubiKey) -> Result<Self> {
        Transaction::new(&mut client.card)?.select_application(
            APPLET_ID,
            APPLET_NAME,
            "failed selecting YkHSM auth application",
        )?;

        Ok(Self { client })
    }

    /// Enable YubiHSM applet
    pub fn enable_yubihsm(&mut self) -> Result<()> {
        let mut config = Transaction::new(&mut self.client.card)?.read_config()?;
        config.config.usb_enabled_apps |= Capability::HSMAUTH;
        Transaction::new(&mut self.client.card)?.write_config(
            self.client.version,
            config.config,
            None,
            None,
        )?;
        Ok(())
    }

    /// Enable PIV applet
    pub fn enable_piv(&mut self) -> Result<()> {
        let mut config = Transaction::new(&mut self.client.card)?.read_config()?;
        config.config.usb_enabled_apps |= Capability::PIV;
        Transaction::new(&mut self.client.card)?.write_config(
            self.client.version,
            config.config,
            None,
            None,
        )?;
        Ok(())
    }

    /// Disable NFC interface on the device
    pub fn disable_nfc(&mut self) -> Result<()> {
        let mut config = Transaction::new(&mut self.client.card)?.read_config()?;
        config.config.nfc_enabled_apps = Some(Capability::empty());
        Transaction::new(&mut self.client.card)?.write_config(
            self.client.version,
            config.config,
            None,
            None,
        )?;
        Ok(())
    }

    /// Lock configuration of the device
    pub fn lock_config(
        &mut self,
        current_lock: Option<Lock>,
        new_lock: Option<Lock>,
    ) -> Result<()> {
        let config = Transaction::new(&mut self.client.card)?.read_config()?;
        Transaction::new(&mut self.client.card)?.write_config(
            self.client.version,
            config.config,
            current_lock,
            new_lock,
        )?;
        Ok(())
    }

    /// Read configuration from yubikey
    pub fn read_config(&mut self) -> Result<DeviceInfo> {
        Transaction::new(&mut self.client.card)?.read_config()
    }

    /// Return the inner [`YubiKey`]
    pub fn into_inner(mut self) -> Result<YubiKey> {
        Transaction::new(&mut self.client.card)?.select_piv_application()?;
        Ok(self.client)
    }
}

/// secret to lock YubiKey's configuration
pub struct Lock(pub [u8; 16]);

impl Lock {
    /// Clear the locking of configuration
    pub const UNLOCKED: Lock = Lock([0; 16]);
}

/// Configuration for a device
#[derive(Clone, Debug, PartialEq)]
#[cfg(feature = "untested")]
pub struct DeviceConfig {
    /// List of applets that are available on the USB interface
    pub usb_enabled_apps: Capability,
    /// List of applets that are available on the NFC interface.
    /// Field will be set to None if the device doesn't support NFC
    pub nfc_enabled_apps: Option<Capability>,
    /// When set, the smartcard will automatically eject after the given time.
    pub auto_eject_timeout: Option<u16>,
    /// The timeout when waiting for touch for challenge response.
    pub challenge_response_timeout: Option<u8>,
    /// Configuration flags
    pub device_flags: Option<DeviceFlags>,
}

#[cfg(feature = "untested")]
impl DeviceConfig {
    pub(crate) fn as_tlv(
        &self,
        reboot: bool,
        current_lock: Option<Lock>,
        new_lock: Option<Lock>,
    ) -> Result<Vec<u8>> {
        let mut data = [0u8; CB_BUF_MAX];
        let mut len = data.len();
        let mut data_remaining = &mut data[1..];

        if reboot {
            let offset = Tlv::write(data_remaining, TAG_REBOOT, &[])?;
            data_remaining = &mut data_remaining[offset..];
        }

        if let Some(lock) = current_lock {
            let offset = Tlv::write(data_remaining, TAG_UNLOCK, &lock.0[..])?;
            data_remaining = &mut data_remaining[offset..];
        }

        {
            let offset = Tlv::write(
                data_remaining,
                TAG_USB_ENABLED,
                &self.usb_enabled_apps.bits().to_be_bytes()[..],
            )?;
            data_remaining = &mut data_remaining[offset..];
        }
        if let Some(nfc_enabled_apps) = self.nfc_enabled_apps {
            let offset = Tlv::write(
                data_remaining,
                TAG_NFC_ENABLED,
                &nfc_enabled_apps.bits().to_be_bytes()[..],
            )?;
            data_remaining = &mut data_remaining[offset..];
        }
        if let Some(auto_eject_timeout) = self.auto_eject_timeout {
            let offset = Tlv::write(
                data_remaining,
                TAG_AUTO_EJECT_TIMEOUT,
                &auto_eject_timeout.to_be_bytes()[..],
            )?;
            data_remaining = &mut data_remaining[offset..];
        }
        if let Some(challenge_response_timeout) = self.challenge_response_timeout {
            let offset = Tlv::write(
                data_remaining,
                TAG_CHALRESP_TIMEOUT,
                &challenge_response_timeout.to_be_bytes()[..],
            )?;
            data_remaining = &mut data_remaining[offset..];
        }
        if let Some(device_flags) = self.device_flags {
            let offset = Tlv::write(
                data_remaining,
                TAG_DEVICE_FLAGS,
                &device_flags.bits().to_be_bytes()[..],
            )?;
            data_remaining = &mut data_remaining[offset..];
        }

        if let Some(lock) = new_lock {
            let offset = Tlv::write(data_remaining, TAG_CONFIG_LOCK, &lock.0[..])?;
            data_remaining = &mut data_remaining[offset..];
        }

        len -= data_remaining.len();
        data[0] = (len - 1) as u8;
        Ok(data[..len].to_vec())
    }

    /// Is the NFC interface active
    pub fn nfc_enabled(&self) -> bool {
        // It happens that the yubikey will disable the NFC interface entirely if every applet is
        // disabled.
        self.nfc_enabled_apps
            .map(|nfc| !nfc.is_empty())
            .unwrap_or(false)
    }
}

#[cfg(feature = "untested")]
bitflags! {
    /// Represents a set of applications.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Capability: u16 {
        /// One Time Password
        const OTP =0x01;
        /// U2F
        const U2F = 0x02;
        /// FIDO2
        const FIDO2 = 0x200;
        /// OATH
        const OATH = 0x20;
        /// PIV
        const PIV = 0x10;
        /// OpenPGP
        const OPENPGP = 0x08;
        /// HSM Auth
        const HSMAUTH = 0x100;

        /// General CCID bit
        const GENERAL_CCID = 0x04;
    }
}

/// Device information
/// This represents the configuration and the status of the device
#[cfg(feature = "untested")]
pub struct DeviceInfo {
    /// Configuration of the YubiKey
    pub config: DeviceConfig,
    /// Is the configuration locked with a password?
    pub is_locked: bool,
}

#[cfg(feature = "untested")]
impl DeviceInfo {
    pub(crate) fn parse(input: &[u8]) -> Result<Self> {
        use nom::{
            bytes::complete::take,
            combinator::{eof, map},
            multi::fold_many1,
            number::complete::{be_u16, be_u32, u8},
        };

        fn u8_parser(i: &[u8]) -> nom::IResult<&[u8], u8> {
            let (i, v) = u8(i)?;
            let (i, _) = eof(i)?;

            Ok((i, v))
        }
        fn u16_parser(i: &[u8]) -> nom::IResult<&[u8], u16> {
            let (i, v) = be_u16(i)?;
            let (i, _) = eof(i)?;

            Ok((i, v))
        }

        fn capability_parser(i: &[u8]) -> nom::IResult<&[u8], Capability> {
            let (i, v) = map(be_u16, Capability::from_bits_retain)(i)?;
            let (i, _) = eof(i)?;

            Ok((i, v))
        }
        fn serial_parser(i: &[u8]) -> nom::IResult<&[u8], Serial> {
            let (i, v) = map(be_u32, Serial)(i)?;
            let (i, _) = eof(i)?;

            Ok((i, v))
        }

        #[derive(Debug, Default)]
        struct Info {
            usb_supported_apps: Option<Capability>,
            usb_enabled_apps: Option<Capability>,
            nfc_supported_apps: Option<Capability>,
            nfc_enabled_apps: Option<Capability>,
            serial: Option<Serial>,
            form_factor: Option<FormFactor>,
            version: Option<Version>,
            auto_eject_timeout: Option<u16>,
            challenge_response_timeout: Option<u8>,
            device_flags: Option<DeviceFlags>,
            is_locked: bool,
        }

        let (input, len) = u8(input).map_err(|_: nom::Err<()>| Error::ParseError)?;
        let (input, rest) = take(len)(input).map_err(|_: nom::Err<()>| Error::ParseError)?;
        let (_, _) = eof(input).map_err(|_: nom::Err<()>| Error::ParseError)?;

        let out = fold_many1(
            |input| Tlv::parse(input).map_err(|_| nom::Err::Error(())),
            || Ok(Info::default()),
            |acc: Result<Info>, tlv| match acc {
                Ok(mut config) => {
                    match tlv.tag {
                        v if v == TAG_USB_SUPPORTED => {
                            config.usb_supported_apps = Some(
                                capability_parser(tlv.value)
                                    .map_err(|_| Error::ParseError)?
                                    .1,
                            );
                            Ok(config)
                        }
                        v if v == TAG_USB_ENABLED => {
                            config.usb_enabled_apps = Some(
                                capability_parser(tlv.value)
                                    .map_err(|_| Error::ParseError)?
                                    .1,
                            );
                            Ok(config)
                        }
                        v if v == TAG_NFC_SUPPORTED => {
                            config.nfc_supported_apps = Some(
                                capability_parser(tlv.value)
                                    .map_err(|_| Error::ParseError)?
                                    .1,
                            );
                            Ok(config)
                        }
                        v if v == TAG_NFC_ENABLED => {
                            config.nfc_enabled_apps = Some(
                                capability_parser(tlv.value)
                                    .map_err(|_| Error::ParseError)?
                                    .1,
                            );
                            Ok(config)
                        }
                        v if v == TAG_SERIAL => {
                            config.serial =
                                Some(serial_parser(tlv.value).map_err(|_| Error::ParseError)?.1);
                            Ok(config)
                        }
                        v if v == TAG_FORM_FACTOR => {
                            config.form_factor = Some(FormFactor::parse(tlv.value)?);
                            Ok(config)
                        }
                        v if v == TAG_VERSION => {
                            config.version = Some(Version::parse(tlv.value)?);
                            Ok(config)
                        }
                        v if v == TAG_AUTO_EJECT_TIMEOUT => {
                            config.auto_eject_timeout =
                                Some(u16_parser(tlv.value).map_err(|_| Error::ParseError)?.1);
                            Ok(config)
                        }
                        v if v == TAG_CHALRESP_TIMEOUT => {
                            config.challenge_response_timeout =
                                Some(u8_parser(tlv.value).map_err(|_| Error::ParseError)?.1);
                            Ok(config)
                        }
                        v if v == TAG_DEVICE_FLAGS => {
                            config.device_flags = Some(
                                DeviceFlags::parse(tlv.value)
                                    .map_err(|_| Error::ParseError)?
                                    .1,
                            );
                            Ok(config)
                        }
                        v if v == TAG_CONFIG_LOCK => {
                            config.is_locked = tlv.value == b"\x01";
                            Ok(config)
                        }
                        // TODO(baloo): implement config lock
                        _unsupported => {
                            // New unsupported tags
                            Ok(config)
                        }
                    }
                }
                err => err,
            },
        )(rest)
        .map_err(|_: nom::Err<()>| Error::ParseError)?
        .1?;

        let Some(usb_enabled_apps) = out.usb_enabled_apps else {
            return Err(Error::ParseError);
        };

        let config = DeviceConfig {
            usb_enabled_apps,
            nfc_enabled_apps: out.nfc_enabled_apps,
            auto_eject_timeout: out.auto_eject_timeout,
            challenge_response_timeout: out.challenge_response_timeout,
            device_flags: out.device_flags,
        };

        Ok(DeviceInfo {
            config,
            is_locked: out.is_locked,
        })
    }
}

/// FormFactor of the YubiKey
#[cfg(feature = "untested")]
#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
pub enum FormFactor {
    /// YubiKey reported an unknown form factor
    Unknown = 0x00,
    /// Full size USB-A YubiKey
    UsbAKeychain = 0x01,
    /// Nano USB-A YubiKey
    UsbANano = 0x02,
    /// Full size USB-C YubiKey
    UsbCKeychain = 0x03,
    /// Nano USB-C YubiKey
    UsbCNano = 0x04,
    /// Lightning // USB-C YubiKey
    UsbCLightning = 0x05,
    /// USB-A YubiKey with a fingerprint reader
    UsbABio = 0x06,
    /// USB-C YubiKey with a fingerprint reader
    UsbCBio = 0x07,
    /// Unsupported form factor
    Unsupported(u8),
}

#[cfg(feature = "untested")]
impl FormFactor {
    fn parse(input: &[u8]) -> Result<Self> {
        use nom::{combinator::eof, number::complete::u8};

        let (i, v) = u8(input).map_err(|_: nom::Err<()>| Error::ParseError)?;
        let (_i, _) = eof(i).map_err(|_: nom::Err<()>| Error::ParseError)?;

        Ok(match v {
            0 => Self::Unknown,
            1 => Self::UsbAKeychain,
            2 => Self::UsbANano,
            3 => Self::UsbCKeychain,
            4 => Self::UsbCNano,
            5 => Self::UsbCLightning,
            6 => Self::UsbABio,
            7 => Self::UsbCBio,
            v => Self::Unsupported(v),
        })
    }
}

#[cfg(feature = "untested")]
bitflags! {
    /// Represents configuration flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct DeviceFlags: u8{
        /// Remote wake-up
        const REMOTE_WAKEUP = 0x40;
        /// Eject
        const Eject = 0x80;
    }
}

#[cfg(feature = "untested")]
impl DeviceFlags {
    fn parse(i: &[u8]) -> nom::IResult<&[u8], Self> {
        use nom::{
            combinator::{eof, map},
            number::complete::u8,
        };

        let (i, v) = map(u8, Self::from_bits_retain)(i)?;
        let (i, _) = eof(i)?;

        Ok((i, v))
    }
}
