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
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "untested")]
use crate::{
    consts::{TAG_ADMIN_FLAGS_1, TAG_ADMIN_SALT, TAG_PROTECTED_MGM},
    metadata::{AdminData, ProtectedData},
    yubikey::YubiKey,
};
use aes::cipher::{BlockDecrypt as AesDec, BlockEncrypt as AesEnc, KeyInit as AesKeyInit};
use aes::{Aes128, Aes192, Aes256};
use des::{
    cipher::{generic_array::GenericArray /*, BlockDecrypt, BlockEncrypt, KeyInit*/},
    TdesEde3,
};
#[cfg(feature = "untested")]
use {
    crate::{
        piv::{ManagementSlotId, SlotAlgorithmId},
        transaction::Transaction,
    },
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

pub(crate) const ADMIN_FLAGS_1_PROTECTED_MGM: u8 = 0x02;
const AES_LEN_128: usize = 16;
const AES_LEN_192: usize = 24;
const AES_LEN_256: usize = 32;
const AES_BLOCK_SIZE: usize = 16;

#[cfg(feature = "untested")]
const CB_ADMIN_SALT: usize = 16;

/// Size of a DES key
const DES_LEN_DES: usize = 8;

/// Size of a 3DES key
pub(crate) const DES_LEN_3DES: usize = DES_LEN_DES * 3;

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
                if is_weak_key(&key) {
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

/// Weak and semi weak DES keys as taken from:
/// %A D.W. Davies
/// %A W.L. Price
/// %T Security for Computer Networks
/// %I John Wiley & Sons
/// %D 1984
const WEAK_DES_KEYS: &[[u8; DES_LEN_DES]] = &[
    // weak keys
    [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
    [0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE],
    [0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E],
    [0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1],
    // semi-weak keys
    [0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE],
    [0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01],
    [0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1],
    [0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E],
    [0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1],
    [0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01],
    [0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE],
    [0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E],
    [0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E],
    [0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01],
    [0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE],
    [0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1],
];

/// Is this 3DES key weak?
///
/// This check is performed automatically when the key is instantiated to
/// ensure no such keys are used.
fn is_weak_key(key: &[u8; DES_LEN_3DES]) -> bool {
    // set odd parity of key
    let mut tmp = Zeroizing::new([0u8; DES_LEN_3DES]);

    for i in 0..DES_LEN_3DES {
        // count number of set bits in byte, excluding the low-order bit - SWAR method
        let mut c = key[i] & 0xFE;

        c = (c & 0x55) + ((c >> 1) & 0x55);
        c = (c & 0x33) + ((c >> 2) & 0x33);
        c = (c & 0x0F) + ((c >> 4) & 0x0F);

        // if count is even, set low key bit to 1, otherwise 0
        tmp[i] = (key[i] & 0xFE) | u8::from(c & 0x01 != 0x01);
    }

    // check odd parity key against table by DES key block
    let mut is_weak = false;

    for weak_key in WEAK_DES_KEYS.iter() {
        if weak_key == &tmp[0..DES_LEN_DES]
            || weak_key == &tmp[DES_LEN_DES..2 * DES_LEN_DES]
            || weak_key == &tmp[2 * DES_LEN_DES..3 * DES_LEN_DES]
        {
            is_weak = true;
            break;
        }
    }

    is_weak
}
