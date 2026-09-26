use std::collections::HashMap;
use std::sync::Arc;

use ironrdp_graphics::pointer::DecodedPointer;

#[derive(Debug, Clone, Default)]
pub struct PointerCache {
    // TODO(@pacancoder) maybe use Vec<Optional<...>> instead?
    cache: HashMap<usize, Arc<DecodedPointer>>,
}

impl PointerCache {
    pub fn insert(&mut self, id: usize, pointer: Arc<DecodedPointer>) -> Option<Arc<DecodedPointer>> {
        self.cache.insert(id, pointer)
    }

    pub fn get(&self, id: usize) -> Option<Arc<DecodedPointer>> {
        self.cache.get(&id).cloned()
    }

    pub fn is_cached(&self, id: usize) -> bool {
        self.cache.contains_key(&id)
    }
}
