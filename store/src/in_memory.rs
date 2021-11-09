use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use log::trace;
use tokio::sync::RwLock;

use crate::MetadataValue;

use super::Store;
use super::StoreError;

type ValueT<V> = (Option<SystemTime>, V, Arc<RwLock<HashMap<String, Vec<u8>>>>);

#[derive(Debug)]
struct MemoryStore<K, V> {
    store: Arc<RwLock<HashMap<K, ValueT<V>>>>,
}

pub(super) fn initialize<OT, K, V, MKT>(
    _cfg: Option<config::Value>,
) -> Result<Box<dyn Store<OT, K, V, MKT>>, StoreError>
where
    OT: crate::StoreOpenMode,
    K: std::string::ToString + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Send + Sync + Clone + 'static,
    MKT: crate::MetadataLocalKey + 'static,
{
    Ok(Box::new(MemoryStore {
        store: Arc::new(RwLock::new(HashMap::new())),
    }))
}

#[async_trait]
impl<OT, K, V, MKT> Store<OT, K, V, MKT> for MemoryStore<K, V>
where
    OT: crate::StoreOpenMode,
    K: std::string::ToString + Eq + std::hash::Hash + Send + Sync,
    V: Send + Sync + Clone,
    MKT: crate::MetadataLocalKey,
{
    async fn load_data(&self, key: &K) -> Result<Option<V>, StoreError> {
        trace!("Looking for entry {}", key.to_string());
        let store = self.store.read().await;
        let data = store.get(key);

        if data.is_none() {
            trace!("Entry not found");
            return Ok(None);
        }
        let (ttl, data, _metadata) = data.unwrap();
        if ttl.is_some() && ttl.unwrap() < SystemTime::now() {
            trace!("Entry had expired");
            return Ok(None);
        }
        trace!("Returning data");
        return Ok(Some(data.clone()));
    }

    async fn store_metadata(
        &self,
        key: &K,
        metadata_key: &crate::MetadataKey<MKT>,
        metadata_value: &dyn MetadataValue,
    ) -> Result<(), StoreError> {
        trace!("Looking for entry {}", key.to_string());
        let store = self.store.read().await;
        let data = store.get(key);

        if data.is_none() {
            trace!("Entry not found");
            return Ok(());
        }

        let (_ttl, _data, metadata_store) = data.unwrap();
        metadata_store.write().await.insert(
            metadata_key.to_key().to_string(),
            metadata_value.to_stored()?,
        );
        Ok(())
    }

    async fn store_data(&self, key: K, ttl: Option<Duration>, value: V) -> Result<(), StoreError> {
        trace!("Storing entry, key {}, TTL {:?}", key.to_string(), ttl);

        let ttl = ttl.map(|d| SystemTime::now() + d);

        self.store
            .write()
            .await
            .insert(key, (ttl, value, Arc::new(RwLock::new(HashMap::new()))));
        Ok(())
    }

    async fn destroy_data(&self, key: &K) -> Result<(), StoreError> {
        trace!("Destroying entry");

        self.store.write().await.remove(key);
        Ok(())
    }

    async fn perform_maintenance(&self) -> Result<(), StoreError> {
        // TODO
        Ok(())
    }
}
