use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::time::SystemTime;

use serde::Deserialize;
use thiserror::Error;

use fdo_data_formats::Serializable;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Unspecified error occured: {0}")]
    Unspecified(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
}

mod private {
    pub trait Sealed {}

    // Implement for those same types, but no others.
    impl Sealed for super::ReadWriteOpen {}
    impl Sealed for super::ReadOnlyOpen {}
    impl Sealed for super::WriteOnlyOpen {}
}

pub trait Readable: private::Sealed {}
pub trait Writable: private::Sealed {}
pub trait StoreOpenMode: private::Sealed {}

pub struct ReadWriteOpen();
impl StoreOpenMode for ReadWriteOpen {}
impl Readable for ReadWriteOpen {}
impl Writable for ReadWriteOpen {}

pub struct ReadOnlyOpen();
impl StoreOpenMode for ReadOnlyOpen {}
impl Readable for ReadOnlyOpen {}

pub struct WriteOnlyOpen();
impl StoreOpenMode for WriteOnlyOpen {}
impl Writable for WriteOnlyOpen {}

pub trait MetadataValue: Send + Sync {
    fn to_stored(&self) -> Result<Vec<u8>, StoreError>;
    fn to_text(&self) -> String;
}

impl MetadataValue for bool {
    fn to_stored(&self) -> Result<Vec<u8>, StoreError> {
        Ok(self.to_string().as_bytes().to_vec())
    }
    fn to_text(&self) -> String {
        self.to_string()
    }
}

impl MetadataValue for Duration {
    fn to_stored(&self) -> Result<Vec<u8>, StoreError> {
        let ttl = SystemTime::now() + *self;
        let ttl = ttl.duration_since(SystemTime::UNIX_EPOCH).map_err(|e| {
            StoreError::Unspecified(format!("Error determining time from epoch to TTL: {:?}", e))
        })?;
        let ttl = ttl.as_secs();
        Ok(u64::to_le_bytes(ttl).into())
    }
    fn to_text(&self) -> String {
        self.as_secs().to_string()
    }
}

pub trait MetadataLocalKey: Send + Sync {
    fn to_key(&self) -> &'static str;
}

#[non_exhaustive]
enum StoreMetadataKey {
    Ttl,
}

impl MetadataLocalKey for StoreMetadataKey {
    fn to_key(&self) -> &'static str {
        match self {
            StoreMetadataKey::Ttl => "user.fdo.store_ttl",
        }
    }
}

pub struct MetadataKey<T: MetadataLocalKey>(T);

impl<T: MetadataLocalKey> MetadataKey<T> {
    fn to_key(&self) -> &str {
        self.to_key()
    }
}

pub trait FilterType<V, MKT>: Send + Sync
where
    V: Clone,
    MKT: MetadataLocalKey,
{
    fn add_eq(&mut self, key: &MetadataKey<MKT>, expected: &dyn MetadataValue);
    fn query<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ValueIter<V>>, StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        Self: 'async_trait;
}

pub struct ValueIter<V: Clone> {
    values: Vec<V>,
    index: usize,
}

impl<V> Iterator for ValueIter<V>
where
    V: Clone,
{
    type Item = V;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.values.len() {
            return None;
        }

        let entry = self.values.get(self.index);
        if let Some(e) = entry {
            self.index += 1;
            return Some(e.clone());
        } else {
            log::warn!("Error getting next entry");
        }

        None
    }
}

pub trait Store<OT: StoreOpenMode, K, V, MKT: MetadataLocalKey>: Send + Sync {
    fn load_data<'life0, 'life1, 'async_trait>(
        &'life0 self,
        key: &'life1 K,
    ) -> Pin<Box<dyn Future<Output = Result<Option<V>, StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
        OT: Readable;

    fn store_metadata<'life0, 'life1, 'life2, 'life3, 'async_trait>(
        &'life0 self,
        key: &'life1 K,
        metadata_key: &'life2 MetadataKey<MKT>,
        metadata_value: &'life3 dyn MetadataValue,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        Self: 'async_trait,
        OT: Writable;

    fn query_data<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn FilterType<V, MKT>>, StoreError>>
                + 'async_trait
                + Send,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
        OT: Writable;

    fn store_data<'life0, 'async_trait>(
        &'life0 self,
        key: K,
        ttl: Option<Duration>,
        value: V,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
        OT: Writable;

    fn destroy_data<'life0, 'life1, 'async_trait>(
        &'life0 self,
        key: &'life1 K,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
        OT: Writable;

    fn perform_maintenance<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
        OT: Writable;
}

#[cfg(feature = "directory")]
mod directory;
// mod in_memory;

#[derive(Debug, Deserialize)]
pub enum StoreDriver {
    // InMemory,
    #[cfg(feature = "directory")]
    Directory,
}

impl StoreDriver {
    pub fn initialize<OT, K, V, MKT>(
        &self,
        cfg: Option<config::Value>,
    ) -> Result<Box<dyn Store<OT, K, V, MKT>>, StoreError>
    where
        OT: StoreOpenMode + 'static,
        // K and V are supersets of the possible requirements for the different implementations
        K: Eq + std::hash::Hash + Send + Sync + std::string::ToString + std::str::FromStr + 'static,
        V: Send + Sync + Clone + Serializable + 'static,
        MKT: crate::MetadataLocalKey + 'static,
    {
        match self {
            // StoreDriver::InMemory => in_memory::initialize(cfg),
            #[cfg(feature = "directory")]
            StoreDriver::Directory => directory::initialize(cfg),
        }
    }
}
