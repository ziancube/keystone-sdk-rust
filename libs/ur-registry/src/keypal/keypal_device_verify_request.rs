use crate::cbor::cbor_map;
use crate::error::{URError, URResult};
use crate::registry_types::{RegistryType, KEYPAL_DEVICE_VERIFY_REQUEST, UUID};
use crate::traits::{From as FromCbor, RegistryItem, To};
use crate::types::Bytes;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use minicbor::data::{Int, Tag};
use minicbor::encode::Write;
use minicbor::{Decoder, Encoder};

const REQUEST_ID: u8 = 1;
const SIGN_DATA: u8 = 2;

#[derive(Clone, Debug, Default)]
pub struct KeypalDeviceVerifyRequest {
    request_id: Option<Bytes>,
    sign_data: Bytes,
}

impl KeypalDeviceVerifyRequest {
    pub fn default() -> Self {
        Default::default()
    }

    pub fn set_request_id(&mut self, request_id: Bytes) {
        self.request_id = Some(request_id);
    }

    pub fn set_sign_data(&mut self, sign_data: Bytes) {
        self.sign_data = sign_data;
    }

    pub fn new(request_id: Bytes, sign_data: Bytes) -> Self {
        KeypalDeviceVerifyRequest {
            request_id: Some(request_id),
            sign_data,
        }
    }

    pub fn get_request_id(&self) -> Option<Bytes> {
        self.request_id.clone()
    }

    pub fn get_sign_data(&self) -> Bytes {
        self.sign_data.clone()
    }
    fn get_map_size(&self) -> u64 {
        let mut size = 1;
        if self.request_id.is_some() {
            size += 1;
        }
        size
    }
}

impl RegistryItem for KeypalDeviceVerifyRequest {
    fn get_registry_type() -> RegistryType<'static> {
        KEYPAL_DEVICE_VERIFY_REQUEST
    }
}

impl<C> minicbor::Encode<C> for KeypalDeviceVerifyRequest {
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

        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for KeypalDeviceVerifyRequest {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let mut result = KeypalDeviceVerifyRequest::default();
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
                _ => {}
            }
            Ok(())
        })?;
        Ok(result)
    }
}

impl To for KeypalDeviceVerifyRequest {
    fn to_bytes(&self) -> URResult<Vec<u8>> {
        minicbor::to_vec(self.clone()).map_err(|e| URError::CborEncodeError(e.to_string()))
    }
}

impl FromCbor<KeypalDeviceVerifyRequest> for KeypalDeviceVerifyRequest {
    fn from_cbor(bytes: Vec<u8>) -> URResult<KeypalDeviceVerifyRequest> {
        minicbor::decode(&bytes).map_err(|e| URError::CborDecodeError(e.to_string()))
    }
}
