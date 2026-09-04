//! The `reqwest-middleware` adapter and in-memory storage for HTTP caching.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use reqwest::{Response, ResponseBuilderExt as _, Url};
use reqwest_middleware::{Middleware, Next};
use zizmor_http_cache::{AfterResponse, BeforeRequest, CachePolicy, CachePolicyBuilder};

const DEFAULT_MAX_ENTRIES: usize = 1_000;

/// Describes how an HTTP response interacted with the cache.
///
/// The value is attached to both the middleware request extensions and the
/// returned response extensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CacheStatus {
    /// No reusable entry existed, so the response came from the network.
    Miss,
    /// A fresh response was served without a network request.
    Hit,
    /// A stale entry was validated by the origin and then reused.
    Revalidated,
}

/// A bounded, process-local HTTP cache middleware.
#[derive(Clone)]
pub(crate) struct HttpCache {
    store: Arc<Mutex<Store>>,
}

impl std::fmt::Debug for HttpCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Ok(store) = self.store.lock() else {
            return formatter
                .debug_struct("HttpCache")
                .field("state", &"poisoned")
                .finish();
        };
        formatter
            .debug_struct("HttpCache")
            .field("entries", &store.entries.len())
            .field("max_entries", &store.max_entries)
            .finish_non_exhaustive()
    }
}

impl HttpCache {
    /// Creates an empty cache retaining at most `max_entries` responses.
    ///
    /// # Panics
    ///
    /// Panics if `max_entries` is zero.
    pub(crate) fn new(max_entries: usize) -> Self {
        assert!(max_entries > 0, "HTTP cache capacity must be non-zero");
        Self {
            store: Arc::new(Mutex::new(Store::new(max_entries))),
        }
    }

    fn lookup(&self, key: &CacheKey) -> Option<CachedResponse> {
        self.store
            .lock()
            .expect("HTTP cache mutex poisoned")
            .get(key)
    }

    fn insert(&self, key: CacheKey, response: CachedResponse) {
        self.store
            .lock()
            .expect("HTTP cache mutex poisoned")
            .insert(key, response);
    }

    fn remove(&self, key: &CacheKey) {
        self.store
            .lock()
            .expect("HTTP cache mutex poisoned")
            .remove(key);
    }

    fn mark(
        mut response: Response,
        extensions: &mut http::Extensions,
        status: CacheStatus,
    ) -> Response {
        extensions.insert(status);
        response.extensions_mut().insert(status);
        response
    }

    async fn store_response(
        &self,
        key: CacheKey,
        policy: CachePolicy,
        response: Response,
        extensions: &mut http::Extensions,
    ) -> reqwest_middleware::Result<Response> {
        if !policy.is_storable() {
            self.remove(&key);
            return Ok(Self::mark(response, extensions, CacheStatus::Miss));
        }

        let cached = CachedResponse::from_response(policy, response).await?;
        let response = cached.to_response(CacheStatus::Miss);
        self.insert(key, cached);
        extensions.insert(CacheStatus::Miss);
        Ok(response)
    }
}

impl Default for HttpCache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES)
    }
}

#[async_trait::async_trait]
impl Middleware for HttpCache {
    async fn handle(
        &self,
        mut request: reqwest::Request,
        extensions: &mut http::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        if request.method() != http::Method::GET && request.method() != http::Method::HEAD {
            let response = next.run(request, extensions).await?;
            return Ok(Self::mark(response, extensions, CacheStatus::Miss));
        }

        let key = CacheKey::from(&request);
        if let Some(cached) = self.lookup(&key) {
            let uri = request.url().as_str().to_owned();
            let method = request.method().clone();
            match cached
                .policy
                .before_request(&uri, &method, request.headers_mut())
            {
                BeforeRequest::Fresh => {
                    extensions.insert(CacheStatus::Hit);
                    return Ok(cached.to_response(CacheStatus::Hit));
                }
                BeforeRequest::Stale(builder) => {
                    let response = next.run(request, extensions).await?;
                    return match cached.policy.after_response(
                        builder,
                        response.status(),
                        response.headers(),
                    ) {
                        AfterResponse::NotModified(policy) => {
                            let cached = cached.revalidated(policy, &response);
                            let response = cached.to_response(CacheStatus::Revalidated);
                            self.insert(key, cached);
                            extensions.insert(CacheStatus::Revalidated);
                            Ok(response)
                        }
                        AfterResponse::Modified(policy) => {
                            self.store_response(key, policy, response, extensions).await
                        }
                    };
                }
                BeforeRequest::NoMatch => {
                    // A URL can have only one retained variant. If `Vary`
                    // makes it unrelated, replace it with the new response.
                    self.remove(&key);
                }
            }
        }

        let builder =
            CachePolicyBuilder::new(request.url().as_str(), request.method(), request.headers());
        let response = next.run(request, extensions).await?;
        let policy = builder.build(response.status(), response.headers());
        self.store_response(key, policy, response, extensions).await
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CacheKey {
    method: http::Method,
    url: Url,
}

impl From<&reqwest::Request> for CacheKey {
    fn from(request: &reqwest::Request) -> Self {
        Self {
            method: request.method().clone(),
            url: request.url().clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct CachedResponse {
    policy: CachePolicy,
    status: http::StatusCode,
    version: http::Version,
    headers: http::HeaderMap,
    body: Bytes,
    url: Url,
}

impl CachedResponse {
    async fn from_response(
        policy: CachePolicy,
        response: Response,
    ) -> reqwest_middleware::Result<Self> {
        let status = response.status();
        let version = response.version();
        let headers = response.headers().clone();
        let url = response.url().clone();
        let body = response.bytes().await?;
        Ok(Self {
            policy,
            status,
            version,
            headers,
            body,
            url,
        })
    }

    fn revalidated(&self, policy: CachePolicy, response: &Response) -> Self {
        let mut cached = self.clone();
        cached.policy = policy;

        // RFC 9111 S4.3.4 updates stored metadata with fields supplied by the
        // 304 response. Keep the stored entity length, since the 304 has no
        // body of its own.
        for name in response.headers().keys() {
            if name == http::header::CONTENT_LENGTH {
                continue;
            }
            cached.headers.remove(name);
            for value in response.headers().get_all(name) {
                cached.headers.append(name, value.clone());
            }
        }
        cached
    }

    fn to_response(&self, cache_status: CacheStatus) -> Response {
        let mut response = http::Response::builder()
            .status(self.status)
            .version(self.version)
            .url(self.url.clone())
            .body(self.body.clone())
            .expect("cached response metadata was already valid");
        *response.headers_mut() = self.headers.clone();
        let mut response = reqwest::Response::from(response);
        response.extensions_mut().insert(cache_status);
        response
    }
}

#[derive(Debug)]
struct Store {
    entries: HashMap<CacheKey, CachedResponse>,
    // Oldest at the front, most recently used at the back.
    order: VecDeque<CacheKey>,
    max_entries: usize,
}

impl Store {
    fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries),
            order: VecDeque::with_capacity(max_entries),
            max_entries,
        }
    }

    fn get(&mut self, key: &CacheKey) -> Option<CachedResponse> {
        let response = self.entries.get(key)?.clone();
        self.touch(key);
        Some(response)
    }

    fn insert(&mut self, key: CacheKey, response: CachedResponse) {
        self.entries.insert(key.clone(), response);
        self.touch(&key);
        while self.entries.len() > self.max_entries {
            let oldest = self
                .order
                .pop_front()
                .expect("cache order cannot be empty while entries remain");
            self.entries.remove(&oldest);
        }
    }

    fn remove(&mut self, key: &CacheKey) {
        self.entries.remove(key);
        if let Some(index) = self.order.iter().position(|candidate| candidate == key) {
            self.order.remove(index);
        }
    }

    fn touch(&mut self, key: &CacheKey) {
        if let Some(index) = self.order.iter().position(|candidate| candidate == key) {
            self.order.remove(index);
        }
        self.order.push_back(key.clone());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use reqwest_middleware::ClientBuilder;

    use super::*;

    #[derive(Clone, Copy)]
    enum Behavior {
        Fresh,
        NoStore,
        Revalidate,
    }

    struct Origin {
        calls: Arc<AtomicUsize>,
        behavior: Behavior,
    }

    #[async_trait::async_trait]
    impl Middleware for Origin {
        async fn handle(
            &self,
            request: reqwest::Request,
            _extensions: &mut http::Extensions,
            _next: Next<'_>,
        ) -> reqwest_middleware::Result<Response> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let mut builder = http::Response::builder().url(request.url().clone());
            let body = match self.behavior {
                Behavior::Fresh => {
                    builder = builder
                        .status(http::StatusCode::OK)
                        .header(http::header::CACHE_CONTROL, "max-age=60");
                    request.url().as_str().as_bytes().to_vec()
                }
                Behavior::NoStore => {
                    builder = builder
                        .status(http::StatusCode::OK)
                        .header(http::header::CACHE_CONTROL, "no-store");
                    b"uncached".to_vec()
                }
                Behavior::Revalidate if call == 0 => {
                    builder = builder
                        .status(http::StatusCode::OK)
                        .header(http::header::CACHE_CONTROL, "max-age=0")
                        .header(http::header::ETAG, "\"version-1\"");
                    b"cached body".to_vec()
                }
                Behavior::Revalidate => {
                    assert_eq!(
                        request.headers()[http::header::IF_NONE_MATCH],
                        "\"version-1\""
                    );
                    builder = builder
                        .status(http::StatusCode::NOT_MODIFIED)
                        .header(http::header::CACHE_CONTROL, "max-age=60")
                        .header(http::header::ETAG, "\"version-1\"");
                    vec![]
                }
            };
            Ok(reqwest::Response::from(
                builder.body(body).expect("mock response is valid"),
            ))
        }
    }

    fn client(
        capacity: usize,
        behavior: Behavior,
    ) -> (reqwest_middleware::ClientWithMiddleware, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let client = ClientBuilder::new(
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("mock HTTP client is valid"),
        )
        .with(HttpCache::new(capacity))
        .with(Origin {
            calls: Arc::clone(&calls),
            behavior,
        })
        .build();
        (client, calls)
    }

    #[tokio::test]
    async fn reuses_fresh_response() {
        let (client, calls) = client(10, Behavior::Fresh);

        let first = client
            .get("https://example.com/data")
            .send()
            .await
            .expect("first request succeeds");
        assert_eq!(
            first.extensions().get::<CacheStatus>(),
            Some(&CacheStatus::Miss)
        );
        let second = client
            .get("https://example.com/data")
            .send()
            .await
            .expect("second request succeeds");
        assert_eq!(
            second.extensions().get::<CacheStatus>(),
            Some(&CacheStatus::Hit)
        );
        assert_eq!(second.url().as_str(), "https://example.com/data");
        assert_eq!(
            second.text().await.expect("cached body can be read"),
            "https://example.com/data"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn does_not_store_no_store_response() {
        let (client, calls) = client(10, Behavior::NoStore);

        client
            .get("https://example.com/data")
            .send()
            .await
            .expect("first request succeeds");
        client
            .get("https://example.com/data")
            .send()
            .await
            .expect("second request succeeds");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn revalidates_stale_response() {
        let (client, calls) = client(10, Behavior::Revalidate);

        client
            .get("https://example.com/data")
            .send()
            .await
            .expect("initial request succeeds");
        let revalidated = client
            .get("https://example.com/data")
            .send()
            .await
            .expect("revalidation request succeeds");
        assert_eq!(
            revalidated.extensions().get::<CacheStatus>(),
            Some(&CacheStatus::Revalidated)
        );
        assert_eq!(
            revalidated
                .text()
                .await
                .expect("revalidated body can be read"),
            "cached body"
        );

        let hit = client
            .get("https://example.com/data")
            .send()
            .await
            .expect("cache-hit request succeeds");
        assert_eq!(
            hit.extensions().get::<CacheStatus>(),
            Some(&CacheStatus::Hit)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn evicts_least_recently_used_entry() {
        let (client, calls) = client(2, Behavior::Fresh);

        for path in ["a", "b", "a", "c", "b"] {
            client
                .get(format!("https://example.com/{path}"))
                .send()
                .await
                .expect("request succeeds");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }
}
