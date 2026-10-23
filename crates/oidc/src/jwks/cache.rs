//! Implementations for instance-based caching of JSON Web Key Set (JWKS).

use std::{
    sync::{Arc, PoisonError, RwLock},
    time::Duration,
};

use tokio::{sync::Mutex, time::Instant};

use crate::jwks::{JwksSource, JwksSourceError, Keys, SigningKey};

/// The provider's signing keys, cached: refreshed once older than their TTL or when a token
/// names a key id not in the cache, at most once per cooldown, and kept when a refresh fails.
pub struct Cache {
    /// The JWKS to fetch
    source: Box<dyn JwksSource>,
    /// The cache of Keys to read/update
    keys: RwLock<Arc<Keys>>,
    /// Held across the fetch, so concurrent refreshes wait for one another. Guards the time of
    /// the last attempt, which the cooldown is measured from.
    last_refresh: Mutex<Instant>,
    /// When the last fetch finished, readable without waiting for [`Self::last_refresh`]: during
    /// a cooldown, lookups learn there is nothing to do without queueing on that lock.
    last_finished: RwLock<Instant>,
    /// How old the keys may get before a lookup refreshes them.
    ttl: Duration,
    /// The cooldown: the least time between two fetches, however many lookups ask for one.
    min_refresh_interval: Duration,
}

impl Cache {
    /// Loads the keys from `source`. They are refreshed once older than `ttl`, and fetched at
    /// most once per `min_refresh_interval`. Fails if `source` cannot be reached.
    pub async fn new(
        source: impl JwksSource + 'static,
        ttl: Duration,
        min_refresh_interval: Duration,
    ) -> Result<Self, JwksSourceError> {
        let now = Instant::now();
        let keys = Keys::from_set(&source.fetch().await?, now);
        Ok(Self {
            source: Box::new(source),
            keys: RwLock::new(Arc::new(keys)),
            last_refresh: Mutex::new(now),
            last_finished: RwLock::new(now),
            ttl,
            min_refresh_interval,
        })
    }

    /// The current key set, without holding the lock.
    fn snapshot(&self) -> Arc<Keys> {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The signing key with id `kid`: from the cache while it is fresh, otherwise after a
    /// refresh. Fails if the provider does not publish it even after a refresh, or could not be
    /// asked about it.
    pub async fn key(&self, kid: &str) -> Result<Arc<SigningKey>, JwksSourceError> {
        let keys = self.snapshot();
        if keys.fetched_at.elapsed() < self.ttl
            && let Some(key) = keys.by_kid.get(kid)
        {
            return Ok(key.clone());
        }

        // Unknown key id, or keys past their ttl
        let (keys, failure) = self.refresh(&keys).await;
        match (keys.by_kid.get(kid), failure) {
            (Some(key), _) => Ok(key.clone()),
            (None, Some(error)) => Err(JwksSourceError::Unreachable(error.to_string())),
            (None, None) => Err(JwksSourceError::SigningKeyNotFound(kid.into())),
        }
    }
    /// Refetches the keys unless another request replaced `seen` meanwhile or the cooldown has
    /// not passed. Returns the keys to use (the previous ones if the fetch failed) and this
    /// call's fetch failure, if any.
    async fn refresh(&self, seen: &Arc<Keys>) -> (Arc<Keys>, Option<JwksSourceError>) {
        // Fast path: a fetch finished within the cooldown and the keys are still the ones seen,
        // so there is nothing to do. Without it, every lookup during a provider outage would
        // queue on the lock only to learn that. A fetch still in flight has not finished, so
        // lookups then wait for its result instead, e.g. a key the provider just rotated in.
        let finished = *self
            .last_finished
            .read()
            .unwrap_or_else(PoisonError::into_inner);

        if finished.elapsed() < self.min_refresh_interval && Arc::ptr_eq(&self.snapshot(), seen) {
            return (seen.clone(), None);
        }

        let mut last_refresh = self.last_refresh.lock().await;

        // Another request refreshed while this one waited for the lock
        let current = self.snapshot();
        if !Arc::ptr_eq(&current, seen) {
            return (current, None);
        }
        if last_refresh.elapsed() < self.min_refresh_interval {
            return (current, None);
        }

        *last_refresh = Instant::now();
        let fetched = self.source.fetch().await;
        *self
            .last_finished
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Instant::now();
        match fetched {
            Ok(set) => {
                let fresh = Arc::new(Keys::from_set(&set, Instant::now()));
                *self.keys.write().unwrap_or_else(PoisonError::into_inner) = fresh.clone();
                (fresh, None)
            }
            Err(error) => {
                tracing::warn!(%error, "Keeping previous signing keys");
                (current, Some(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use jsonwebtoken::jwk::JwkSet;

    use crate::jwks::{JwksSource, JwksSourceError, cache::Cache, fixtures::key_set};

    /// Key TTL in the tests.
    const TTL: Duration = Duration::from_secs(600);
    /// Refresh cooldown in the tests.
    const COOLDOWN: Duration = Duration::from_secs(30);

    /// A key source the test controls, counting fetches.
    #[derive(Debug)]
    struct TestSource {
        /// What the next fetch returns; `None` fails it.
        response: Arc<Mutex<Option<JwkSet>>>,
        /// How many fetches happened.
        fetches: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl JwksSource for TestSource {
        async fn fetch(&self) -> Result<JwkSet, JwksSourceError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.response
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| JwksSourceError::Unreachable("connection refused".into()))
        }
    }

    /// A cache over a [`TestSource`], with handles to control and observe it.
    struct CacheTestState {
        /// The cache under test.
        cache: Cache,
        /// What the source's next fetch returns.
        response: Arc<Mutex<Option<JwkSet>>>,
        /// How many fetches the source served.
        fetches: Arc<AtomicUsize>,
    }

    impl CacheTestState {
        /// A cache loaded with placeholder keys `kids`.
        async fn new(kids: &[&str]) -> Self {
            let response = Arc::new(Mutex::new(Some(key_set(kids))));
            let fetches = Arc::new(AtomicUsize::new(0));
            let source = TestSource {
                response: response.clone(),
                fetches: fetches.clone(),
            };
            let cache = Cache::new(source, TTL, COOLDOWN).await.unwrap();
            Self {
                cache,
                response,
                fetches,
            }
        }

        /// Makes the next fetches return `set`, or fail if `None`.
        fn serve(&self, set: Option<JwkSet>) {
            *self.response.lock().unwrap() = set
        }

        /// How many fetches happened so far.
        fn fetches(&self) -> usize {
            self.fetches.load(Ordering::SeqCst)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_known_kid_when_queried_then_it_should_only_fetch_once() {
        let state = CacheTestState::new(&["a"]).await;
        state.cache.key("a").await.unwrap();
        assert_eq!(state.fetches(), 1);
        state.cache.key("a").await.unwrap();
        assert_eq!(state.fetches(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_rotated_key_when_queried_then_it_should_refetch_once() {
        let state = CacheTestState::new(&["a"]).await;
        state.cache.key("a").await.unwrap();
        assert_eq!(state.fetches(), 1);
        tokio::time::advance(COOLDOWN).await;
        state.serve(Some(key_set(&["a", "b"])));

        assert!(state.cache.key("b").await.is_ok());
        assert_eq!(state.fetches(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn given_an_unknown_key_within_the_min_refresh_interval_when_queried_then_it_should_not_refresh()
     {
        let state = CacheTestState::new(&["a"]).await;
        let result = state.cache.key("not-a-key").await;

        assert!(matches!(
            result,
            Err(JwksSourceError::SigningKeyNotFound(kid)) if kid == "not-a-key"
        ));
        assert_eq!(state.fetches(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn given_concurrent_unknown_kids_when_queried_then_it_should_refetch_once() {
        let state = CacheTestState::new(&["a"]).await;
        state.cache.key("a").await.unwrap();
        assert_eq!(state.fetches(), 1);
        tokio::time::advance(COOLDOWN).await;
        state.serve(Some(key_set(&["a", "b"])));

        // Three ask for the rotated-in key at once; the second and third must not skip the in-flight fetch.
        let (first, second, third) = tokio::join!(
            state.cache.key("b"),
            state.cache.key("b"),
            state.cache.key("b"),
        );

        assert!(first.is_ok() && second.is_ok() && third.is_ok());
        assert_eq!(state.fetches(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn given_keys_older_than_ttl_when_queried_then_it_should_refetch() {
        let state = CacheTestState::new(&["a"]).await;
        tokio::time::advance(TTL).await;
        state.cache.key("a").await.unwrap();
        assert_eq!(state.fetches(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_failed_refresh_when_a_known_kid_is_queried_then_it_should_return_the_old_key()
    {
        let state = CacheTestState::new(&["a"]).await;
        tokio::time::advance(TTL).await;
        state.serve(None);
        assert!(state.cache.key("a").await.is_ok());
        assert_eq!(state.fetches(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_failed_refresh_when_an_unknown_kid_is_queried_then_it_should_return_an_error()
    {
        let state = CacheTestState::new(&["a"]).await;
        tokio::time::advance(COOLDOWN).await;
        state.serve(None);

        let result = state.cache.key("b").await;
        assert!(matches!(result, Err(JwksSourceError::Unreachable(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_failed_refresh_when_looked_up_during_the_cooldown_then_it_does_not_wait_for_the_lock()
     {
        let state = CacheTestState::new(&["a"]).await;
        tokio::time::advance(TTL).await;
        state.serve(None);
        assert!(state.cache.key("a").await.is_ok(), "old key is kept");

        let _held = state.cache.last_refresh.lock().await;
        let lookup = tokio::time::timeout(Duration::from_secs(1), state.cache.key("a")).await;

        assert!(lookup.is_ok(), "answered without queuing the lock");
        assert_eq!(state.fetches(), 2, "and without another fetch");
    }

    #[tokio::test(start_paused = true)]
    async fn given_an_unreachable_source_at_startup_when_created_then_it_should_return_an_error() {
        let source = TestSource {
            response: Arc::new(Mutex::new(None)),
            fetches: Arc::new(AtomicUsize::new(0)),
        };
        assert!(Cache::new(source, TTL, COOLDOWN).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_key_removed_by_the_provider_when_queried_after_the_ttl_then_it_should_be_rejected()
     {
        let state = CacheTestState::new(&["a", "b"]).await;
        state.serve(Some(key_set(&["b"])));
        tokio::time::advance(TTL).await;

        let result = state.cache.key("a").await;

        assert!(matches!(
            result,
            Err(JwksSourceError::SigningKeyNotFound(kid)) if kid == "a"
        ));
        assert_eq!(state.fetches(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn given_a_failed_refresh_when_the_cooldown_passes_then_it_should_retry_and_recover() {
        let state = CacheTestState::new(&["a"]).await;
        tokio::time::advance(COOLDOWN).await;
        state.serve(None);
        let during_outage = state.cache.key("b").await;
        assert!(matches!(
            during_outage,
            Err(JwksSourceError::Unreachable(_))
        ));

        state.serve(Some(key_set(&["a", "b"])));
        tokio::time::advance(COOLDOWN).await;

        assert!(state.cache.key("b").await.is_ok());
        assert_eq!(state.fetches(), 3);
    }
}
