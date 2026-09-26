//! Adapters: map a native request / response pair onto the engine.

pub(crate) mod create_adapter;

pub use create_adapter::{
    AdapterBuildError,
    CustomAdapter,
    CustomAdapterHandlers,
    create_adapter,
};
