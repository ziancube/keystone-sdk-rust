use crate::cbor::cbor_map;
use crate::crypto_key_path::CryptoKeyPath;
use crate::error::{URError, URResult};
use crate::registry_types::{RegistryType, CRYPTO_KEYPATH, KEYPAL_TRON_SIGN_REQUEST, UUID};
use crate::traits::{From as FromCbor, RegistryItem, To};
use crate::types::Bytes;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use minicbor::data::{Int, Tag};
use minicbor::encode::Write;
use minicbor::{Decoder, Encoder};

const REQUEST_ID: u8 = 1;
const SIGN_DATA: u8 = 2;
const DERIVATION_PATH: u8 = 3;
const ADDRESS: u8 = 4;
const ORIGIN: u8 = 5;
const SIGN_TYPE: u8 = 6;
const CHAIN_ID: u8 = 7;

#[derive(Clone, Debug, PartialEq, Default)]
pub enum SignType {
    #[default]
    Transaction = 1,
    Message,
}

impl SignType {
    pub fn from_u32(i: u32) -> Result<Self, String> {
        match i {
            1 => Ok(SignType::Transaction),
            2 => Ok(SignType::Message),
            x => Err(format!(
                "invalid value for sign_type in keypal-tron-sign-request, expected 1 or 2, received {:?}",
                x
            )),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct KeypalTronSignRequest {
    request_id: Option<Bytes>,
    sign_data: Bytes,
    derivation_path: CryptoKeyPath,
    address: Option<Bytes>,
    origin: Option<String>,
    sign_type: SignType,
    chain_id: Option<String>, 
}

impl KeypalTronSignRequest {
    pub fn default() -> Self {
        Default::default()
    }

    pub fn set_request_id(&mut self, id: Bytes) {
        self.request_id = Some(id);
    }

    pub fn set_sign_data(&mut self, data: Bytes) {
        self.sign_data = data;
    }

    pub fn set_derivation_path(&mut self, derivation_path: CryptoKeyPath) {
        self.derivation_path = derivation_path;
    }

    pub fn set_address(&mut self, address: Bytes) {
        self.address = Some(address)
    }

    pub fn set_origin(&mut self, origin: String) {
        self.origin = Some(origin)
    }

    pub fn set_sign_type(&mut self, sign_type: SignType) {
        self.sign_type = sign_type
    }

    pub fn set_chain_id(&mut self, chain_id: String) {
        self.chain_id = Some(chain_id)
    }

    pub fn new(
        request_id: Option<Bytes>,
        sign_data: Bytes,
        derivation_path: CryptoKeyPath,
        address: Option<Bytes>,
        origin: Option<String>,
        sign_type: SignType,
        chain_id: Option<String>,
    ) -> KeypalTronSignRequest {
        KeypalTronSignRequest {
            request_id,
            sign_data,
            derivation_path,
            address,
            origin,
            sign_type,
            chain_id,
        }
    }
    pub fn get_request_id(&self) -> Option<Bytes> {
        self.request_id.clone()
    }
    pub fn get_sign_data(&self) -> Bytes {
        self.sign_data.clone()
    }
    pub fn get_derivation_path(&self) -> CryptoKeyPath {
        self.derivation_path.clone()
    }
    pub fn get_address(&self) -> Option<Bytes> {
        self.address.clone()
    }
    pub fn get_origin(&self) -> Option<String> {
        self.origin.clone()
    }
    pub fn get_sign_type(&self) -> SignType {
        self.sign_type.clone()
    }

    pub fn get_chain_id(&self) -> Option<String> {
        self.chain_id.clone()
    }

    fn get_map_size(&self) -> u64 {
        let mut size = 3;
        if self.request_id.is_some() {
            size += 1;
        }
        if self.address.is_some() {
            size += 1;
        }
        if self.origin.is_some() {
            size += 1;
        }
        size
    }
}

impl RegistryItem for KeypalTronSignRequest {
    fn get_registry_type() -> RegistryType<'static> {
        KEYPAL_TRON_SIGN_REQUEST
    }
}

impl<C> minicbor::Encode<C> for KeypalTronSignRequest {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(self.get_map_size())?;

        if let Some(request_id) = &self.request_id {
            e.int(Int::from(REQUEST_ID))?
                .tag(Tag::Unassigned(UUID.get_tag()))?
                .bytes(request_id)?;
        }

        e.int(Int::from(SIGN_DATA))?.bytes(&self.sign_data)?;

        e.int(Int::from(DERIVATION_PATH))?;
        e.tag(Tag::Unassigned(CRYPTO_KEYPATH.get_tag()))?;
        CryptoKeyPath::encode(&self.derivation_path, e, _ctx)?;

        if let Some(address) = &self.address {
            e.int(Int::from(ADDRESS))?.bytes(address)?;
        }

        if let Some(origin) = &self.origin {
            e.int(Int::from(ORIGIN))?.str(origin)?;
        }

        e.int(Int::from(SIGN_TYPE))?
            .int(Int::from(self.sign_type.clone() as u8))?;

        if let Some(chain_id) = &self.chain_id {
            e.int(Int::from(CHAIN_ID))?.str(chain_id)?;
        }

        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for KeypalTronSignRequest {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let mut result = KeypalTronSignRequest::default();
        cbor_map(d, &mut result, |key, obj, d| {
            let key =
                u8::try_from(key).map_err(|e| minicbor::decode::Error::message(e.to_string()))?;
            match key {
                REQUEST_ID => {
                    d.tag()?;
                    obj.request_id = Some(d.bytes()?.to_vec());
                }
                SIGN_DATA => {
                    obj.sign_data = d.bytes()?.to_vec();
                }
                DERIVATION_PATH => {
                    d.tag()?;
                    obj.derivation_path = CryptoKeyPath::decode(d, _ctx)?;
                }
                ADDRESS => {
                    obj.address = Some(d.bytes()?.to_vec());
                }
                ORIGIN => {
                    obj.origin = Some(d.str()?.to_string());
                }
                SIGN_TYPE => {
                    obj.sign_type = SignType::from_u32(
                        u32::try_from(d.int()?)
                            .map_err(|e| minicbor::decode::Error::message(e.to_string()))?,
                    )
                    .map_err(minicbor::decode::Error::message)?;
                }
                CHAIN_ID => {
                    obj.chain_id = Some(d.str()?.to_string());
                }
                _ => {}
            }
            Ok(())
        })?;
        Ok(result)
    }
}

impl To for KeypalTronSignRequest {
    fn to_bytes(&self) -> URResult<Vec<u8>> {
        minicbor::to_vec(self.clone()).map_err(|e| URError::CborEncodeError(e.to_string()))
    }
}

impl FromCbor<KeypalTronSignRequest> for KeypalTronSignRequest {
    fn from_cbor(bytes: Vec<u8>) -> URResult<KeypalTronSignRequest> {
        minicbor::decode(&bytes).map_err(|e| URError::CborDecodeError(e.to_string()))
    }
}