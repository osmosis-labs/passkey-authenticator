use cw_storage_plus::Item;

use crate::admin::Admin;

/// Admin address, Optional.
pub const ADMIN: Item<Admin> = Item::new("admin");
pub const ADDRESS: Item<String> = Item::new("pubKey");
