use crate::cbor::cbor_map;
use crate::error::{URError, URResult};
use crate::registry_types::{RegistryType, KEYPAL_DEVICE_INFO};
use crate::traits::{From as FromCbor, RegistryItem, To};
use crate::types::Bytes;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use minicbor::data::{Int, Tag};
use minicbor::encode::Write;
use minicbor::{Decoder, Encoder};

const FEATURES: u8 = 1;
const CERTIFICATE: u8 = 2;

#[derive(Clone, Debug, Default)]
pub struct KeypalDeviceInfo {
    features: Bytes,
    certificate: String,
}

impl KeypalDeviceInfo {
    pub fn default() -> Self {
        Default::default()
    }

    pub fn set_features(&mut self, features: Bytes) {
        self.features = features;
    }

    pub fn set_certificate(&mut self, certificate: String) {
        self.certificate = certificate;
    }

    pub fn new(features: Bytes, certificate: String) -> Self {
        KeypalDeviceInfo {
            features,
            certificate,
        }
    }

    pub fn get_features(&self) -> Bytes {
        self.features.clone()
    }

    pub fn get_certificate(&self) -> String {
        self.certificate.clone()
    }
}

impl RegistryItem for KeypalDeviceInfo {
    fn get_registry_type() -> RegistryType<'static> {
        KEYPAL_DEVICE_INFO
    }
}

impl<C> minicbor::Encode<C> for KeypalDeviceInfo {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let mut size = 0;
        if !self.features.is_empty() {
            size += 1;
        }
        if !self.certificate.is_empty() {
            size += 1;
        }
        e.map(size)?;
        if !self.features.is_empty() {
            e.int(Int::from(FEATURES))?.bytes(&self.features)?;
        }
        if !self.certificate.is_empty() {
            e.int(Int::from(CERTIFICATE))?.str(&self.certificate)?;
        }

        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for KeypalDeviceInfo {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let mut result = KeypalDeviceInfo::default();
        cbor_map(d, &mut result, |key, obj, d| {
            let key =
                u8::try_from(key).map_err(|e| minicbor::decode::Error::message(e.to_string()))?;
            match key {
                FEATURES => {
                    obj.features = d.bytes()?.to_vec();
                }
                CERTIFICATE => {
                    obj.certificate = d.str()?.to_string();
                }
                _ => {}
            }
            Ok(())
        })?;
        Ok(result)
    }
}

impl To for KeypalDeviceInfo {
    fn to_bytes(&self) -> URResult<Vec<u8>> {
        minicbor::to_vec(self.clone()).map_err(|e| URError::CborEncodeError(e.to_string()))
    }
}

impl FromCbor<KeypalDeviceInfo> for KeypalDeviceInfo {
    fn from_cbor(bytes: Vec<u8>) -> URResult<KeypalDeviceInfo> {
        minicbor::decode(&bytes).map_err(|e| URError::CborDecodeError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::keypal::keypal_device_info::KeypalDeviceInfo;
    use crate::traits::{From as FromCbor, To};
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use hex::FromHex;

    #[test]
    fn test_encode() {
        let features = Some(
            [
                155, 29, 235, 77, 59, 125, 75, 173, 155, 221, 43, 13, 123, 61, 203, 109,
            ]
            .to_vec(),
        );
        let certificate = [
            212, 240, 167, 188, 217, 91, 186, 31, 187, 16, 81, 136, 80, 84, 115, 14, 63, 71, 6, 66,
            136, 87, 90, 172, 193, 2, 251, 191, 106, 154, 20, 218, 160, 102, 153, 30, 54, 13, 62,
            52, 6, 194, 12, 0, 164, 9, 115, 239, 243, 124, 125, 100, 30, 91, 53, 30, 196, 169, 155,
            254, 134, 243, 53, 247, 19,
        ]
        .to_vec();
        let keypal_device_info = KeypalDeviceInfo::new(features, certificate.to_string());
        assert_eq!(
            "a301d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d025841d4f0a7bcd95bba1fbb1051885054730e3f47064288575aacc102fbbf6a9a14daa066991e360d3e3406c20c00a40973eff37c7d641e5b351ec4a99bfe86f335f71303686b657973746f6e65",
            hex::encode(keypal_device_info.to_bytes().unwrap()).to_lowercase()
        );
    }

    #[test]
    fn test_decode() {
        let bytes = Vec::from_hex(
            "a301d825509b1deb4d3b7d4bad9bdd2b0d7b3dcb6d025841d4f0a7bcd95bba1fbb1051885054730e3f47064288575aacc102fbbf6a9a14daa066991e360d3e3406c20c00a40973eff37c7d641e5b351ec4a99bfe86f335f71303686b657973746f6e65",
        )
            .unwrap();
        let keypal_device_info = KeypalDeviceInfo::from_cbor(bytes).unwrap();
        assert_eq!(
            [155, 29, 235, 77, 59, 125, 75, 173, 155, 221, 43, 13, 123, 61, 203, 109].to_vec(),
            keypal_device_info.get_features().unwrap()
        );
        assert_eq!(
            [
                212, 240, 167, 188, 217, 91, 186, 31, 187, 16, 81, 136, 80, 84, 115, 14, 63, 71, 6,
                66, 136, 87, 90, 172, 193, 2, 251, 191, 106, 154, 20, 218, 160, 102, 153, 30, 54,
                13, 62, 52, 6, 194, 12, 0, 164, 9, 115, 239, 243, 124, 125, 100, 30, 91, 53, 30,
                196, 169, 155, 254, 134, 243, 53, 247, 19
            ]
            .to_vec(),
            keypal_device_info.get_certificate()
        );
    }
}
