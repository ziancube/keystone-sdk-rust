use crate::cbor::{cbor_array, cbor_map};
use crate::extend::key_derivation_schema::{Curve, DerivationAlgo};
use crate::impl_template_struct;
use crate::registry_types::{
    RegistryType, KEYPAL_ACCOUNTS_REQUEST, KEYPAL_CRYPTO_MULTI_ACCOUNTS_REQUEST,
};
use crate::traits::{MapSize, RegistryItem};
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use minicbor::data::{Int, Tag};
use minicbor::encode::{Error, Write};
use minicbor::{Decoder, Encoder};

const KEY_PATH: u8 = 1;
const CURVE: u8 = 2;
const ALGO: u8 = 3;
const CHAIN_TYPE: u8 = 4;

impl_template_struct!(AccountRequest {
    key_path: String,
    curve: Option<Curve>,
    algo: Option<DerivationAlgo>,
    chain_type: Option<String>
});

impl AccountRequest {
    pub fn get_curve_or_default(&self) -> Curve {
        match self.get_curve() {
            Some(c) => c,
            None => Curve::Secp256k1,
        }
    }
    pub fn get_algo_or_default(&self) -> DerivationAlgo {
        match self.get_algo() {
            Some(a) => a,
            None => DerivationAlgo::Slip10,
        }
    }
}

impl RegistryItem for AccountRequest {
    fn get_registry_type() -> RegistryType<'static> {
        KEYPAL_ACCOUNTS_REQUEST
    }
}

impl MapSize for AccountRequest {
    fn map_size(&self) -> u64 {
        let mut size = 1;
        if let Some(_) = self.curve {
            size += 1;
        }
        if let Some(_) = self.algo {
            size += 1;
        }

        if let Some(_) = self.chain_type {
            size += 1;
        }
        size
    }
}

impl<C> minicbor::Encode<C> for AccountRequest {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, _ctx: &mut C) -> Result<(), Error<W::Error>> {
        e.map(self.map_size())?;

        e.int(Int::from(KEY_PATH))?.str(&self.key_path)?;

        if let Some(curve) = &self.curve {
            e.int(Int::from(CURVE))?
                .int(Int::from(curve.clone() as u32))?;
        }

        if let Some(algo) = &self.algo {
            e.int(Int::from(ALGO))?
                .int(Int::from(algo.clone() as u32))?;
        }
        if let Some(chain_type) = &self.chain_type {
            e.int(Int::from(CHAIN_TYPE))?.str(&chain_type)?;
        }
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for AccountRequest {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let mut result = AccountRequest::default();
        cbor_map(d, &mut result, |key, obj, d| {
            let key =
                u8::try_from(key).map_err(|e| minicbor::decode::Error::message(e.to_string()))?;
            match key {
                KEY_PATH => {
                    let key_path = String::try_from(d.str()?)
                        .map_err(|e| minicbor::decode::Error::message(e.to_string()))?;
                    obj.set_key_path(key_path);
                }
                CURVE => {
                    let curve = Curve::try_from(
                        u32::try_from(d.int()?)
                            .map_err(|e| minicbor::decode::Error::message(e.to_string()))?,
                    )
                    .map_err(|e| minicbor::decode::Error::message(e.to_string()))?;
                    obj.set_curve(Some(curve))
                }
                ALGO => {
                    let algo = DerivationAlgo::try_from(
                        u32::try_from(d.int()?)
                            .map_err(|e| minicbor::decode::Error::message(e.to_string()))?,
                    )
                    .map_err(|e| minicbor::decode::Error::message(e.to_string()))?;
                    obj.set_algo(Some(algo))
                }
                CHAIN_TYPE => {
                    let chain_type = String::try_from(d.str()?)
                        .map_err(|e| minicbor::decode::Error::message(e.to_string()))?;
                    obj.set_chain_type(Some(chain_type))
                }
                _ => {}
            }
            Ok(())
        })?;
        Ok(result)
    }
}

const KEY_PATHS: u8 = 1;
const ORIGIN: u8 = 2;

impl_template_struct!(KeypalCryptoMultiAccountsRequest {
    paths: Vec<AccountRequest>,
    origin: Option<String>
});

impl RegistryItem for KeypalCryptoMultiAccountsRequest {
    fn get_registry_type() -> RegistryType<'static> {
        KEYPAL_CRYPTO_MULTI_ACCOUNTS_REQUEST
    }
}

impl MapSize for KeypalCryptoMultiAccountsRequest {
    fn map_size(&self) -> u64 {
        /// size = paths + version
        let mut size = 1;
        size = match self.origin {
            Some(_) => size + 1,
            None => size,
        };

        size
    }
}

impl<C> minicbor::Encode<C> for KeypalCryptoMultiAccountsRequest {
    fn encode<W: Write>(&self, e: &mut Encoder<W>, ctx: &mut C) -> Result<(), Error<W::Error>> {
        e.map(self.map_size())?;
        e.int(Int::from(KEY_PATHS))?
            .array(self.get_paths().len() as u64)?;
        for path in self.get_paths() {
            e.tag(Tag::Unassigned(KEYPAL_ACCOUNTS_REQUEST.get_tag()))?;
            path.encode(e, ctx)?;
        }

        if let Some(origin) = self.get_origin() {
            e.int(Int::from(ORIGIN))?.str(&origin)?;
        }

        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for KeypalCryptoMultiAccountsRequest {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let mut result = KeypalCryptoMultiAccountsRequest::default();
        cbor_map(d, &mut result, |key, obj, d| {
            let key =
                u8::try_from(key).map_err(|e| minicbor::decode::Error::message(e.to_string()))?;
            match key {
                KEY_PATHS => {
                    let mut paths = vec![];
                    cbor_array(d, obj, |_index, _obj, d| {
                        d.tag()?;
                        paths.push(AccountRequest::decode(d, ctx)?);
                        Ok(())
                    })?;
                    obj.set_paths(paths)
                }
                ORIGIN => {
                    let origin = d.str()?.to_string();
                    obj.set_origin(Some(origin))
                }

                _ => {}
            }
            Ok(())
        })?;

        Ok(result)
    }
}
