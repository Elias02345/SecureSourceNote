//! Stable identities for the MVP object spine (master §5.3).
//!
//! Durable identity uses opaque stable IDs, never visual labels. Object IDs
//! (`WorkspaceId`, `DocumentId`, `BlockId`) are assigned by the client; the core
//! stores and validates them. `OpId` is content-derived (see [`crate::envelope`]),
//! which gives tamper-evidence and idempotent dedup on replay/sync.
//!
//! Distinct newtypes (not bare `String`) so the compiler rejects passing a
//! `DocumentId` where a `BlockId` is expected.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.0)
            }
        }
    };
}

id_type!(AccountId); // identity layer; enrollment lands in ROADMAP S3
id_type!(DeviceId);
id_type!(WorkspaceId);
id_type!(DocumentId);
id_type!(BlockId);
id_type!(OpId); // content-derived (hex SHA-256 of the envelope core)
