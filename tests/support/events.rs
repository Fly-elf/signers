//! Captures the `tracing` events a run emits, for the tests of the event contract.
//!
//! Subscribers installed with `set_default` are thread-local, so the code under
//! test has to be driven on the calling thread: a current-thread runtime (the
//! async API) or the blocking API, which builds its own on the calling thread.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use tracing::field::{Field, Visit};
use tracing::{Level, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::{Layer, registry};

/// One captured event. Every field value is kept as its `Display` text, except
/// those recorded with `?`, which are kept as their `Debug` text.
#[derive(Debug, Clone)]
pub struct Event {
    pub level: Level,
    pub target: String,
    pub message: String,
    pub fields: BTreeMap<String, String>,
}

impl Event {
    pub fn field(&self, name: &str) -> &str {
        self.fields
            .get(name)
            .unwrap_or_else(|| panic!("event {:?} has no field `{name}`: {self:?}", self.message))
    }
}

struct Collector(Arc<Mutex<Vec<Event>>>);

struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

impl<S: Subscriber> Layer<S> for Collector {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let mut fields = Fields(BTreeMap::new());
        event.record(&mut fields);
        let message = fields.0.remove("message").unwrap_or_default();
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Event {
                level: *event.metadata().level(),
                target: event.metadata().target().to_owned(),
                message,
                fields: fields.0,
            });
    }
}

/// Runs `run` with a subscriber that records every event emitted on this thread,
/// at any level and under any target.
///
/// ```ignore
/// let (result, events) = events::capture(|| sign_adhoc(&target).run());
/// ```
pub fn capture<R>(run: impl FnOnce() -> R) -> (R, Vec<Event>) {
    let events = Arc::default();
    let subscriber = registry().with(Collector(Arc::clone(&events)));
    let result = {
        let _default = tracing::subscriber::set_default(subscriber);
        run()
    };
    let events = std::mem::take(&mut *events.lock().unwrap_or_else(PoisonError::into_inner));
    (result, events)
}

/// Runs `future` on a current-thread runtime built on this thread, capturing
/// its events as [`capture`] does.
pub fn capture_async<F: std::future::Future>(future: F) -> (F::Output, Vec<Event>) {
    capture(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("could not build a tokio runtime")
            .block_on(future)
    })
}

/// The events whose message is `message`, in order.
pub fn named<'a>(events: &'a [Event], message: &str) -> Vec<&'a Event> {
    events.iter().filter(|e| e.message == message).collect()
}

/// The messages of `events`, in order.
pub fn messages(events: &[Event]) -> Vec<&str> {
    events.iter().map(|e| e.message.as_str()).collect()
}
