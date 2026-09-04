// This module is derived from uv's HTTP cache implementation:
// https://github.com/astral-sh/uv/tree/a600759b93304d64c9e0c003b6559841982d5b1d/crates/uv-client/src/httpcache
// Copyright (c) 2025 Astral Software Inc. Used under the MIT license; see
// ../LICENSE-UV.

use std::time::{Duration, SystemTime};

use http::header::HeaderValue;

use crate::control::CacheControl;

/// Knobs to configure cache behavior.
///
/// At time of writing, we don't expose any way of modifying these since I
/// suspect we won't ever need to. We split them out into their own type so
/// that they can be shared between `CachePolicyBuilder` and `CachePolicy`.
#[derive(Clone, Debug, Default)]
struct CacheConfig {
    shared: bool,
}

/// A builder for constructing a [`CachePolicy`].
///
/// A builder can be used directly when spawning fresh HTTP requests
/// without a cached response. A builder is also constructed for you via
/// [`CachePolicy::before_request`] when a cached response exists but is stale.
///
/// The main idea of a builder is that it manages the flow of data needed to
/// construct a [`CachePolicy`]. That is, you start with HTTP request metadata,
/// then you get response metadata and finally a new [`CachePolicy`].
#[derive(Debug)]
pub struct CachePolicyBuilder {
    /// The configuration controlling the behavior of the cache.
    config: CacheConfig,
    /// A subset of information from the HTTP request that we will store. This
    /// is needed to make future decisions about cache behavior.
    request: StoredRequest,
    /// The full set of request headers. This copy is necessary because the
    /// headers are needed in order to correctly capture the values necessary
    /// to implement the `Vary` check, as per [RFC 9111 S4.1]. The upside is
    /// that this is not actually persisted in a [`CachePolicy`]. We only need
    /// it until we have the response.
    ///
    /// The precise reason why this copy is intrinsically needed is because
    /// sending a request requires ownership of the request. Yet, we don't know
    /// which header values we need to store in our cache until we get the
    /// response back. Thus, these headers must be persisted until after the
    /// point we've given up ownership of the request.
    ///
    /// [RFC 9111 S4.1]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1
    request_headers: http::HeaderMap,
}

impl CachePolicyBuilder {
    /// Create a new builder of a cache policy, starting with the request
    /// metadata.
    pub fn new(uri: &str, method: &http::Method, headers: &http::HeaderMap) -> Self {
        Self {
            config: CacheConfig::default(),
            request: StoredRequest::new(uri, method, headers),
            request_headers: headers.clone(),
        }
    }

    /// Return a new policy given the response metadata for the request that
    /// this builder was created with.
    pub fn build(self, status: http::StatusCode, headers: &http::HeaderMap) -> CachePolicy {
        let vary = Vary::from_request_response_headers(&self.request_headers, headers);
        CachePolicy {
            config: self.config,
            request: self.request,
            response: StoredResponse::new(status, headers),
            vary,
        }
    }
}

/// A value encapsulating the data needed to implement HTTP caching behavior.
///
/// A cache policy is meant to be stored with the data being cached. It is
/// specifically meant to capture the smallest amount of information needed
/// to determine whether a cached response is stale or not, and the information
/// required to issue a re-validation request.
///
/// This does not provide a complete set of HTTP cache semantics. Notably
/// absent from this (among other things that zizmor probably doesn't care
/// about) are proxy cache semantics.
#[derive(Clone, Debug)]
pub struct CachePolicy {
    /// The configuration controlling the behavior of the cache.
    config: CacheConfig,
    /// A subset of information from the HTTP request that we will store. This
    /// is needed to make future decisions about cache behavior.
    request: StoredRequest,
    /// A subset of information from the HTTP response that we will store. This
    /// is needed to make future decisions about cache behavior.
    response: StoredResponse,
    /// This contains the set of vary header names (from the cached response)
    /// and the corresponding values (from the original request) used to verify
    /// whether a new request can utilize a cached response or not. This is
    /// placed outside of `request` and `response` because it contains bits
    /// from both!
    vary: Vary,
}

impl CachePolicy {
    /// Determines what caching behavior is correct given an existing
    /// [`CachePolicy`] and a new HTTP request for the resource managed by this
    /// cache policy. This is done as per [RFC 9111 S4].
    ///
    /// Calling this method conceptually corresponds to asking the following
    /// question: "I have a cached response for an incoming HTTP request. May I
    /// return that cached response, or do I need to go back to the progenitor
    /// of that response to determine whether it's still the latest thing?"
    ///
    /// This returns one of three possible behaviors:
    ///
    /// 1. The cached response is still fresh, and the caller may return the
    ///    cached response without issuing an HTTP request.
    /// 2. The cached response is stale. The caller should send a re-validation
    ///    request and then call [`CachePolicy::after_response`] to determine
    ///    whether the cached response is actually fresh, or if it's stale and
    ///    needs to be updated.
    /// 3. The given request does not match the cache policy identification.
    ///    Generally speaking, this usually implies a bug with the cache in that
    ///    it loaded a cache policy that does not match the request.
    ///
    /// In the case of (2), the given request headers are modified in place
    /// such that they are suitable for a revalidation request.
    ///
    /// [RFC 9111 S4]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4
    pub fn before_request(
        &self,
        uri: &str,
        method: &http::Method,
        headers: &mut http::HeaderMap,
    ) -> BeforeRequest {
        let now = SystemTime::now();

        // If the response was never storable, then we just bail out
        // completely.
        if !self.is_storable() {
            tracing::trace!(
                "Request {} does not match cache request {} because it isn't storable",
                uri,
                self.request.uri,
            );
            return BeforeRequest::NoMatch;
        }
        // "When presented with a request, a cache MUST NOT reuse a stored
        // response unless..."
        //
        // "the presented target URI and that of the stored response match,
        // and..."
        if self.request.uri != uri {
            tracing::trace!(
                "Request {} does not match cache URL of {}",
                uri,
                self.request.uri,
            );
            return BeforeRequest::NoMatch;
        }
        // "the request method associated with the stored response allows it to
        // be used for the presented request, and..."
        if method != http::Method::GET && method != http::Method::HEAD {
            tracing::trace!(
                "Method {:?} for request {} is not supported by this cache",
                method,
                uri,
            );
            return BeforeRequest::NoMatch;
        }

        // "Request header fields nominated by the stored response (if any)
        // match those presented, and..."
        //
        // If `Vary` does not match, we conservatively require revalidation.
        if !self.vary.matches(headers) {
            tracing::trace!(
                "Request {} does not match cached request because of the 'Vary' header",
                uri,
            );
            self.set_revalidation_headers(headers);
            return BeforeRequest::Stale(Box::new(
                self.new_cache_policy_builder(uri, method, headers),
            ));
        }
        // "the stored response does not contain the no-cache directive, unless
        // it is successfully validated, and..."
        if self.response.headers.cc.no_cache {
            self.set_revalidation_headers(headers);
            return BeforeRequest::Stale(Box::new(
                self.new_cache_policy_builder(uri, method, headers),
            ));
        }
        // "the stored response is one of the following: ..."
        //
        // "fresh, or..."
        // "allowed to be served stale, or..."
        if self.is_fresh(now, uri, headers) {
            return BeforeRequest::Fresh;
        }

        // "successfully validated."
        //
        // In this case, callers will need to send a revalidation request.
        self.set_revalidation_headers(headers);
        BeforeRequest::Stale(Box::new(
            self.new_cache_policy_builder(uri, method, headers),
        ))
    }

    /// This implements the logic for handling the response to a request that
    /// may be a revalidation request, as per [RFC 9111 S4.3.3] and [RFC 9111
    /// S4.3.4]. That is, the cache policy builder given here should be the one
    /// returned by [`CachePolicy::before_request`] with the response received
    /// from the origin server for the possibly-revalidating request.
    ///
    /// Even if the request is new (in that there is no response cached
    /// for it), callers may use this routine. But generally speaking,
    /// callers are only supposed to use this routine after getting a
    /// [`BeforeRequest::Stale`].
    ///
    /// The return value indicates whether the cached response is still fresh
    /// (that is, [`AfterResponse::NotModified`]) or if it has changed (that is,
    /// [`AfterResponse::Modified`]). In the latter case, the cached response
    /// has been invalidated and the caller should cache the new response. In
    /// the former case, the cached response is still considered fresh.
    ///
    /// In either case, callers should update their cache with the new policy.
    ///
    /// [RFC 9111 S4.3.3]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.3
    /// [RFC 9111 S4.3.4]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.4
    pub fn after_response(
        &self,
        cache_policy_builder: Box<CachePolicyBuilder>,
        status: http::StatusCode,
        headers: &http::HeaderMap,
    ) -> AfterResponse {
        let mut new_policy = cache_policy_builder.build(status, headers);
        if self.is_modified(&new_policy) {
            AfterResponse::Modified(new_policy)
        } else {
            new_policy.response.status = self.response.status;
            // RFC 9111 S4.3.4 requires updating the stored response with
            // metadata supplied by the 304. When a relevant field is omitted,
            // retain its value from the stored policy instead of accidentally
            // discarding it while constructing the new policy from the 304.
            if !headers.contains_key(http::header::CACHE_CONTROL) {
                new_policy.response.headers.cc = self.response.headers.cc.clone();
            }
            if !headers.contains_key(http::header::EXPIRES) {
                new_policy.response.headers.expires_unix_timestamp =
                    self.response.headers.expires_unix_timestamp;
            }
            if !headers.contains_key(http::header::LAST_MODIFIED) {
                new_policy.response.headers.last_modified_unix_timestamp =
                    self.response.headers.last_modified_unix_timestamp;
            }
            if !headers.contains_key(http::header::ETAG) {
                new_policy.response.headers.etag = self.response.headers.etag.clone();
            }
            if !headers.contains_key(http::header::VARY) {
                new_policy.vary = self.vary.clone();
            }
            AfterResponse::NotModified(new_policy)
        }
    }

    fn is_modified(&self, new_policy: &Self) -> bool {
        // From [RFC 9111 S4.3.3],
        //
        // "A 304 (Not Modified) response status code indicates that the stored
        // response can be updated and reused"
        //
        // So if we don't get a 304, then we know our cached response is seen
        // as stale by the origin server.
        //
        // [RFC 9111 S4.3.3]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.3
        if new_policy.response.status != 304 {
            tracing::trace!(
                "Resource is modified because status is {:?} and not 304",
                new_policy.response.status,
            );
            return true;
        }

        // As per [RFC 9111 S4.3.4], we need to confirm that our validators
        // match. Here, we check `ETag`. We don't support weak validators, so
        // only match if they're both strong.
        //
        // [RFC 9111 S4.3.4]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.4
        if let (Some(old_etag), Some(new_etag)) = (
            self.response.headers.etag.as_ref(),
            new_policy.response.headers.etag.as_ref(),
        ) && !old_etag.weak
            && !new_etag.weak
            && old_etag.value == new_etag.value
        {
            tracing::trace!(
                "Resource is not modified because old and new etag values ({:?}) match",
                new_etag.value,
            );
            return false;
        }

        // As per [RFC 9111 S4.3.4], we need to confirm that our validators
        // match. Here, we check `Last-Modified`.
        //
        // [RFC 9111 S4.3.4]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.4
        if let (Some(old_last_modified), Some(new_last_modified)) = (
            self.response.headers.last_modified_unix_timestamp,
            new_policy.response.headers.last_modified_unix_timestamp,
        ) && old_last_modified == new_last_modified
        {
            tracing::trace!(
                "Resource is not modified because modified times ({new_last_modified:?}) match",
            );
            return false;
        }

        // As per [RFC 9111 S4.3.4], if we have no validators anywhere, then
        // we can just rely on the HTTP 304 status code and reuse the cached
        // response.
        //
        // [RFC 9111 S4.3.4]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.4
        let has_validators = self.response.headers.etag.is_some()
            || new_policy.response.headers.etag.is_some()
            || self.response.headers.last_modified_unix_timestamp.is_some()
            || new_policy
                .response
                .headers
                .last_modified_unix_timestamp
                .is_some();
        if !has_validators {
            tracing::trace!(
                "Resource is not modified because there are no etags or last modified \
                 timestamps, so we assume the 304 status is correct",
            );
        }
        has_validators
    }

    /// Sets the relevant headers so that the request can be used as a
    /// revalidation request. As per [RFC 9111 S4.3.1], this permits the origin
    /// server to check if the content is different from our cached response.
    /// If it isn't, then the origin server can return an HTTP 304 NOT MODIFIED
    /// status, which avoids the need to re-transmit the response body. That is,
    /// it indicates that our cached response is still fresh.
    ///
    /// This will always use a strong etag validator if it's present on the
    /// cached response. If the given request already has an etag validator on
    /// it, this routine will add to it and not replace it.
    ///
    /// In contrast, if the request already has the `If-Modified-Since` header
    /// set, then this will not change or replace it. If it's not set, then one
    /// is added if the cached response had a valid `Last-Modified` header.
    ///
    /// [RFC 9111 S4.3.1]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.1
    fn set_revalidation_headers(&self, headers: &mut http::HeaderMap) {
        // As per [RFC 9110 S13.1.2] and [RFC 9111 S4.3.1], if our stored
        // response has an etag, we should send it back via the `If-None-Match`
        // header. The idea is that the server should only "do" the request if
        // none of the tags match. If there is a match, then the server can
        // return HTTP 304 indicating that our stored response is still fresh.
        //
        // We don't support weak validation principally because we want to be
        // notified if there was a change in the content. Namely, from RFC 9110
        // S13.1.2: "... weak entity tags can be used for cache validation even
        // if there have been changes to the representation data."
        //
        // [RFC 9110 S13.1.2]: https://www.rfc-editor.org/rfc/rfc9110#section-13.1.2
        // [RFC 9111 S4.3.1]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.1
        if let Some(etag) = self.response.headers.etag.as_ref()
            && !etag.weak
            && let Ok(header) = HeaderValue::from_bytes(&etag.value)
        {
            headers.append("if-none-match", header);
        }

        // We also set `If-Modified-Since` as per [RFC 9110 S13.1.3] and [RFC
        // 9111 S4.3.1]. Generally, `If-None-Match` will override this, but we
        // set it in case `If-None-Match` is not supported.
        //
        // [RFC 9110 S13.1.3]: https://www.rfc-editor.org/rfc/rfc9110#section-13.1.3
        // [RFC 9111 S4.3.1]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.1
        if !headers.contains_key("if-modified-since")
            && let Some(last_modified) = self.response.headers.last_modified_unix_timestamp
            && let Some(header) = unix_timestamp_to_header(last_modified)
        {
            headers.insert("if-modified-since", header);
        }
    }

    /// Returns true if and only if the response is storable as per
    /// [RFC 9111 S3].
    ///
    /// [RFC 9111 S3]: https://www.rfc-editor.org/rfc/rfc9111.html#section-3
    pub fn is_storable(&self) -> bool {
        // In the absence of other signals, we are limited to caching responses
        // with a code that is heuristically cacheable as per [RFC 9110 S15.1].
        //
        // [RFC 9110 S15.1]: https://www.rfc-editor.org/rfc/rfc9110#section-15.1
        const HEURISTICALLY_CACHEABLE_STATUS_CODES: &[u16] =
            &[200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501];

        // N.B. This routine could be "simpler", but we bias toward
        // following the flow of logic as closely as possible as written
        // in RFC 9111 S3.

        // "the request method is understood by the cache"
        //
        // We just don't bother with anything that isn't GET or HEAD.
        if !matches!(self.request.method, Method::Get | Method::Head) {
            tracing::trace!(
                "Response from {} is not storable because of the request method {:?}",
                self.request.uri,
                self.request.method,
            );
            return false;
        }
        // "the response status code is final"
        //
        // ... and we'll put more restrictions on status code
        // below, but we can bail out early here.
        if !self.response.has_final_status() {
            tracing::trace!(
                "Response from {} is not storable because it has \
                 a non-final status code {:?}",
                self.request.uri,
                self.response.status,
            );
            return false;
        }
        // "if the response status code is 206 or 304, or the must-understand
        // cache directive (see Section 5.2.2.3) is present: the cache
        // understands the response status code"
        //
        // We don't currently support `must-understand`. We also don't support
        // partial content (206). And 304 not modified shouldn't be cached
        // itself.
        if self.response.status == 206 || self.response.status == 304 {
            tracing::trace!(
                "Response from {} is not storable because it has \
                 an unsupported status code {:?}",
                self.request.uri,
                self.response.status,
            );
            return false;
        }
        // "The no-store request directive indicates that a cache MUST NOT
        // store any part of either this request or any response to it."
        //
        // (This is from RFC 9111 S5.2.1.5, and doesn't seem to be mentioned in
        // S3.)
        if self.request.headers.cc.no_store {
            tracing::trace!(
                "Response from {} is not storable because its request has \
                 a 'no-store' cache-control directive",
                self.request.uri,
            );
            return false;
        }
        // "the no-store cache directive is not present in the response"
        if self.response.headers.cc.no_store {
            tracing::trace!(
                "Response from {} is not storable because it has \
                 a 'no-store' cache-control directive",
                self.request.uri,
            );
            return false;
        }

        // "if the cache is shared ..."
        if self.config.shared {
            // "if the cache is shared: the private response directive is either
            // not present or allows a shared cache to store a modified response"
            //
            // We don't support more granular "private" directives (which allow
            // caching all of a private HTTP response in a shared cache only after
            // removing some subset of the response's headers that are deemed
            // private).
            if self.response.headers.cc.private {
                tracing::trace!(
                    "Response from {} is not storable because this is a shared \
                     cache and has a 'private' cache-control directive",
                    self.request.uri,
                );
                return false;
            }
            // "if the cache is shared: the Authorization header field is not
            // present in the request or a response directive is present that
            // explicitly allows shared caching"
            if self.request.headers.authorization && !self.allows_authorization_storage() {
                tracing::trace!(
                    "Response from {} is not storable because this is a shared \
                     cache and the request has an 'Authorization' header set and \
                     the response has not indicated that caching requests with an \
                     'Authorization' header is allowed",
                    self.request.uri,
                );
                return false;
            }
        }

        // "the response contains at least one of the following ..."
        //
        // "a public response directive"
        if self.response.headers.cc.public {
            tracing::trace!(
                "Response from {} is storable because it has \
                 a 'public' cache-control directive",
                self.request.uri,
            );
            return true;
        }
        // "a private response directive, if the cache is not shared"
        if !self.config.shared && self.response.headers.cc.private {
            tracing::trace!(
                "Response from {} is storable because this is not a shared \
                 cache and it has a 'private' cache-control directive",
                self.request.uri,
            );
            return true;
        }
        // "an Expires header field"
        if self.response.headers.expires_unix_timestamp.is_some() {
            tracing::trace!(
                "Response from {} is storable because it has an \
                 'Expires' header set",
                self.request.uri,
            );
            return true;
        }
        // "a max-age response directive"
        if self.response.headers.cc.max_age_seconds.is_some() {
            tracing::trace!(
                "Response from {} is storable because it has a \
                 'max-age' cache-control directive",
                self.request.uri,
            );
            return true;
        }
        // "if the cache is shared: an s-maxage response directive"
        if self.config.shared && self.response.headers.cc.s_maxage_seconds.is_some() {
            tracing::trace!(
                "Response from {} is storable because this is a shared cache \
                 and has a 's-maxage' cache-control directive",
                self.request.uri,
            );
            return true;
        }
        // "a cache extension that allows it to be cached"
        // ... we don't support any extensions.
        //
        // "a status code that is defined as heuristically cacheable"
        if HEURISTICALLY_CACHEABLE_STATUS_CODES.contains(&self.response.status) {
            tracing::trace!(
                "Response from {} is storable because it has a \
                 heuristically cacheable status code {:?}",
                self.request.uri,
                self.response.status,
            );
            return true;
        }
        tracing::trace!(
            "Response from {} is not storable because it does not meet any \
             of the necessary criteria (e.g., it doesn't have an 'Expires' \
             header set or a 'max-age' cache-control directive)",
            self.request.uri,
        );
        false
    }

    /// Returns true when a response is storable even if it has an
    /// `Authorization` header, as per [RFC 9111 S3.5].
    ///
    /// [RFC 9111 S3.5]: https://www.rfc-editor.org/rfc/rfc9111.html#section-3.5
    fn allows_authorization_storage(&self) -> bool {
        self.response.headers.cc.must_revalidate
            || self.response.headers.cc.public
            || self.response.headers.cc.s_maxage_seconds.is_some()
    }

    /// Returns true if the response is considered fresh as per [RFC 9111
    /// S4.2]. If the response is not fresh, then it is considered stale and
    /// ought to be revalidated with the origin server.
    ///
    /// [RFC 9111 S4.2]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2
    fn is_fresh(&self, now: SystemTime, uri: &str, headers: &http::HeaderMap) -> bool {
        let freshness_lifetime = self.freshness_lifetime().as_secs();
        let age = self.age(now).as_secs();
        let request_cache_control = headers
            .get_all("cache-control")
            .iter()
            .collect::<CacheControl>();

        // Per RFC 8246, the `immutable` directive means that a reload from an
        // end user should not result in a revalidation request. Indeed, the
        // `immutable` directive seems to imply that clients should never talk
        // to the origin server until the cached response is stale with respect
        // to its freshness lifetime (as set by the server).
        //
        // A *force* reload from an end user should override this, but we
        // currently have no path for that in this implementation. Instead, we
        // just interpret `immutable` as meaning that any directives on the
        // new request that would otherwise result in sending a revalidation
        // request are ignored.
        //
        // [RFC 8246]: https://httpwg.org/specs/rfc8246.html
        if !self.response.headers.cc.immutable {
            // As per [RFC 9111 S5.2.1.4], if the request has `no-cache`, then
            // we should respect that.
            //
            // [RFC 9111 S5.2.1.4]: https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.4
            if request_cache_control.no_cache {
                tracing::trace!(
                    "Request to {} does not have a fresh cache entry because \
                     it has a 'no-cache' cache-control directive",
                    uri,
                );
                return false;
            }
            // If the request has a max-age directive, then we should respect
            // that as per [RFC 9111 S5.2.1.1].
            //
            // [RFC 9111 S5.2.1.1]: https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.1
            if let Some(max_age) = request_cache_control.max_age_seconds
                && age > max_age
            {
                tracing::trace!(
                    "Request to {} does not have a fresh cache entry because \
                     the cached response's age is {} seconds and the max age \
                     allowed by the request is {} seconds",
                    uri,
                    age,
                    max_age,
                );
                return false;
            }
            // If the request has a min-fresh directive, then we only consider
            // a cached response fresh if the remaining time it has to live
            // exceeds the threshold provided, as per [RFC 9111 S5.2.1.3].
            //
            // Note that S5.2.1.3 does not say that max-stale overrides this,
            // so we ignore it here.
            //
            // [RFC 9111 S5.2.1.3]: https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.3
            if let Some(min_fresh) = request_cache_control.min_fresh_seconds {
                let time_to_live = freshness_lifetime.saturating_sub(age);
                if time_to_live < min_fresh {
                    tracing::trace!(
                        "Request to {} does not have a fresh cache entry because \
                         the request set a 'min-fresh' cache-control directive, \
                         and its time-to-live is {} seconds but it needs to be \
                         at least {} seconds",
                        uri,
                        time_to_live,
                        min_fresh,
                    );
                    return false;
                }
            }
        }

        // RFC 9111 S4.2 defines freshness as
        // `freshness_lifetime > current_age`, so equality is stale.
        //
        // [RFC 9111 S4.2]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2
        if age >= freshness_lifetime {
            let allows_stale = self.allows_stale(now, request_cache_control.max_stale_seconds);
            if !allows_stale {
                tracing::trace!(
                    "Request to {} does not have a fresh cache entry because \
                     its age is {} seconds, it is greater than or equal to the \
                     freshness lifetime of {} seconds and stale cached responses \
                     are not allowed",
                    uri,
                    age,
                    freshness_lifetime,
                );
                return false;
            }
        }
        true
    }

    /// Returns true if we're allowed to serve a stale response, as per [RFC
    /// 9111 S4.2.4].
    ///
    /// [RFC 9111 S4.2.4]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.4
    fn allows_stale(&self, now: SystemTime, max_stale_seconds: Option<u64>) -> bool {
        // As per [RFC 9111 S5.2.2.2], if `must-revalidate` is present, then
        // caches cannot reuse a stale response without talking to the server
        // first. Note that RFC 9111 doesn't seem to say anything about the
        // interaction between must-revalidate and max-stale, so we assume that
        // must-revalidate takes precedent.
        //
        // [RFC 9111 S5.2.2.2]: https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.2
        if self.response.headers.cc.must_revalidate {
            tracing::trace!(
                "Request to {} has a cached response that does not \
                 permit staleness because the response has a 'must-revalidate' \
                 cache-control directive set",
                self.request.uri,
            );
            return false;
        }
        if let Some(max_stale) = max_stale_seconds {
            // As per [RFC 9111 S5.2.1.2], if the current request has max-stale
            // set, then stale responses are allowed, but only if they are
            // stale within the given threshold.
            //
            // [RFC 9111 S5.2.1.2]: https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.1.2
            let stale_amount = self
                .age(now)
                .as_secs()
                .saturating_sub(self.freshness_lifetime().as_secs());
            if stale_amount <= max_stale {
                tracing::trace!(
                    "Request to {} has a cached response that allows staleness \
                     in this case because the stale amount is {} seconds and the \
                     'max-stale' cache-control directive set by the current request \
                     is {} seconds",
                    self.request.uri,
                    stale_amount,
                    max_stale,
                );
                return true;
            }
        }
        // As per [RFC 9111 S4.2.4], we shouldn't use stale responses unless
        // we're explicitly allowed to (e.g., via `max-stale` above):
        //
        // "A cache MUST NOT generate a stale response unless it is
        // disconnected or doing so is explicitly permitted by the client or
        // origin server..."
        //
        // [RFC 9111 S4.2.4]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.4
        tracing::trace!(
            "Request to {} has a cached response that does not allow staleness",
            self.request.uri,
        );
        false
    }

    /// Returns the age of the HTTP response as per [RFC 9111 S4.2.3].
    ///
    /// The age of a response, essentially, refers to how long it has been
    /// since the response was created by the origin server. The age is used
    /// to compare with the freshness lifetime of the response to determine
    /// whether the response is fresh or stale.
    ///
    /// [RFC 9111 S4.2.3]: https://www.rfc-editor.org/rfc/rfc9111.html#name-calculating-age
    fn age(&self, now: SystemTime) -> Duration {
        // RFC 9111 S4.2.3
        let apparent_age = self
            .response
            .unix_timestamp
            .saturating_sub(self.response.header_date());
        let response_delay = self
            .response
            .unix_timestamp
            .saturating_sub(self.request.unix_timestamp);
        let corrected_age_value = self.response.header_age().saturating_add(response_delay);
        let corrected_initial_age = apparent_age.max(corrected_age_value);
        let resident_age = unix_timestamp(now).saturating_sub(self.response.unix_timestamp);
        Duration::from_secs(corrected_initial_age.saturating_add(resident_age))
    }

    /// Returns how long a response should be considered "fresh" as per
    /// [RFC 9111 S4.2.1]. When this returns zero, the response should be
    /// considered stale and the client should revalidate with the server.
    ///
    /// If there are no indicators of a response's freshness lifetime, then
    /// this returns `0`. That is, the response will be considered stale in all
    /// cases.
    ///
    /// [RFC 9111 S4.2.1]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.1
    fn freshness_lifetime(&self) -> Duration {
        if self.config.shared
            && let Some(s_maxage) = self.response.headers.cc.s_maxage_seconds
        {
            let duration = Duration::from_secs(s_maxage);
            tracing::trace!(
                "Freshness lifetime found via shared \
                 cache-control max age setting: {duration:?}",
            );
            return duration;
        }
        if let Some(max_age) = self.response.headers.cc.max_age_seconds {
            let duration = Duration::from_secs(max_age);
            tracing::trace!(
                "Freshness lifetime found via cache-control max age setting: {duration:?}",
            );
            return duration;
        }
        if let Some(expires) = self.response.headers.expires_unix_timestamp {
            let duration = Duration::from_secs(expires.saturating_sub(self.response.header_date()));
            tracing::trace!("Freshness lifetime found via expires header: {duration:?}");
            return duration;
        }
        if self.response.headers.last_modified_unix_timestamp.is_some() {
            // We previously computed this heuristic freshness lifetime by
            // looking at the difference between the last modified header and
            // the response's date header. We then asserted that the cached
            // response ought to be "fresh" for 10% of that interval.
            //
            // It turns out that this can result in very long freshness
            // lifetimes[1] that lead to caching too aggressively.
            //
            // Since PyPI sets a max-age of 600 seconds, uv uses that as a
            // conservative default. We retain that behavior here instead of
            // reintroducing the aggressive 10%-of-age heuristic.
            //
            // Note though that a better solution here is for the origin to
            // support proper HTTP caching headers (ideally Cache-Control, but
            // Expires also works too, as above).
            //
            // [1]: https://github.com/astral-sh/uv/issues/5351#issuecomment-2260588764
            let duration = Duration::from_secs(10 * 60);
            tracing::trace!(
                "Freshness lifetime heuristically assumed \
                 because of presence of last-modified header: {duration:?}",
            );
            return duration;
        }
        // Without any indicators as to the freshness lifetime, we act
        // conservatively and use a value that will always result in a response
        // being treated as stale.
        tracing::trace!("Could not determine freshness lifetime, assuming none exists");
        Duration::ZERO
    }

    fn new_cache_policy_builder(
        &self,
        uri: &str,
        method: &http::Method,
        headers: &http::HeaderMap,
    ) -> CachePolicyBuilder {
        CachePolicyBuilder {
            config: self.config.clone(),
            request: StoredRequest::new(uri, method, headers),
            request_headers: headers.clone(),
        }
    }
}

/// The result of calling [`CachePolicy::before_request`].
///
/// This dictates what the caller should do next by indicating whether the
/// cached response is stale or not.
#[derive(Debug)]
pub enum BeforeRequest {
    /// The cached response is still fresh, and the caller may return the
    /// cached response without issuing an HTTP request.
    Fresh,
    /// The cached response is stale. The caller should send a re-validation
    /// request and then call [`CachePolicy::after_response`] to determine
    /// whether the cached response is actually fresh, or if it's stale and
    /// needs to be updated.
    Stale(Box<CachePolicyBuilder>),
    /// The given request does not match the cache policy identification.
    /// Generally speaking, this usually implies a bug with the cache in that
    /// it loaded a cache policy that does not match the request.
    NoMatch,
}

/// The result of calling [`CachePolicy::after_response`].
///
/// This is meant to report whether a revalidation request was successful or
/// not. If it was, then [`AfterResponse::NotModified`] is returned. Otherwise,
/// the server determined the cached response was truly stale and in need of
/// updating.
#[derive(Debug)]
pub enum AfterResponse {
    /// The cached response is still fresh.
    NotModified(CachePolicy),
    /// The cached response has been invalidated and needs to be updated with
    /// the new data in the response to the revalidation request.
    Modified(CachePolicy),
}

/// The subset of request information needed for cache decisions.
#[derive(Clone, Debug)]
struct StoredRequest {
    uri: String,
    method: Method,
    headers: RequestHeaders,
    unix_timestamp: u64,
}

impl StoredRequest {
    fn new(uri: &str, method: &http::Method, headers: &http::HeaderMap) -> Self {
        Self {
            uri: uri.to_owned(),
            method: Method::from(method),
            headers: RequestHeaders::from(headers),
            unix_timestamp: unix_timestamp(SystemTime::now()),
        }
    }
}

#[derive(Clone, Debug)]
struct RequestHeaders {
    /// The cache control directives from the `Cache-Control` header.
    cc: CacheControl,
    /// This is set to `true` only when an `Authorization` header is present.
    /// We don't need to record the value.
    authorization: bool,
}

impl From<&http::HeaderMap> for RequestHeaders {
    fn from(headers: &http::HeaderMap) -> Self {
        Self {
            cc: headers.get_all("cache-control").iter().collect(),
            authorization: headers.contains_key("authorization"),
        }
    }
}

/// The HTTP method used on a request.
///
/// We don't bother representing methods of requests whose responses we won't
/// cache. Instead, we treat them as "unrecognized" and consider the responses
/// not-storable.
#[derive(Clone, Debug)]
enum Method {
    Get,
    Head,
    Unrecognized,
}

impl From<&http::Method> for Method {
    fn from(method: &http::Method) -> Self {
        if method == http::Method::GET {
            Self::Get
        } else if method == http::Method::HEAD {
            Self::Head
        } else {
            Self::Unrecognized
        }
    }
}

#[derive(Clone, Debug)]
struct StoredResponse {
    status: u16,
    headers: ResponseHeaders,
    unix_timestamp: u64,
}

impl StoredResponse {
    /// Returns the "age" header value on this response, with a fallback of `0`
    /// if the header doesn't exist or is invalid, as per [RFC 9111 S4.2.3].
    ///
    /// Note that this does not reflect the true "age" of a response. That
    /// is computed via [`CachePolicy::age`] as it may need additional
    /// information (such as the request time).
    ///
    /// [RFC 9111 S4.2.3]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.3
    fn header_age(&self) -> u64 {
        self.headers.age_seconds.unwrap_or(0)
    }

    /// Returns the "date" header value on this response, with a fallback to
    /// the time the response was received as per [RFC 9110 S6.6.1].
    ///
    /// [RFC 9110 S6.6.1]: https://www.rfc-editor.org/rfc/rfc9110#section-6.6.1
    fn header_date(&self) -> u64 {
        self.headers
            .date_unix_timestamp
            .unwrap_or(self.unix_timestamp)
    }

    /// Returns true when this response has a status code that is considered
    /// "final" as per [RFC 9110 S15].
    ///
    /// [RFC 9110 S15]: https://www.rfc-editor.org/rfc/rfc9110#section-15
    fn has_final_status(&self) -> bool {
        self.status >= 200
    }
}

impl StoredResponse {
    fn new(status: http::StatusCode, headers: &http::HeaderMap) -> Self {
        Self {
            status: status.as_u16(),
            headers: ResponseHeaders::from(headers),
            unix_timestamp: unix_timestamp(SystemTime::now()),
        }
    }
}

#[derive(Clone, Debug)]
struct ResponseHeaders {
    /// The directives from the `Cache-Control` header.
    cc: CacheControl,
    /// The value of the `Age` header corresponding to `age_value` as defined
    /// in [RFC 9111 S4.2.3]. If the `Age` header is not present, it should be
    /// interpreted as `0`.
    ///
    /// [RFC 9111 S4.2.3]: https://www.rfc-editor.org/rfc/rfc9111.html#name-calculating-age
    age_seconds: Option<u64>,
    /// This is `date_value` from [RFC 9111 S4.2.3], which says it corresponds
    /// to the `Date` header on a response as defined in [RFC 7231 S7.1.1.2].
    /// In RFC 7231, if the `Date` header is not present, then the recipient
    /// should treat its value as equivalent to the time the response was
    /// received. In this case, that would be `StoredResponse::unix_timestamp`.
    ///
    /// [RFC 9111 S4.2.3]: https://www.rfc-editor.org/rfc/rfc9111.html#name-calculating-age
    /// [RFC 7231 S7.1.1.2]: https://httpwg.org/specs/rfc7231.html#header.date
    date_unix_timestamp: Option<u64>,
    /// This is from the `Expires` header as per [RFC 9111 S5.3]. Note that this
    /// is overridden by the presence of either the `max-age` or `s-maxage`
    /// cache control directives.
    ///
    /// If an `Expires` header was present but did not contain a valid RFC 2822
    /// datetime, then this is `None`.
    ///
    /// [RFC 9111 S5.3]: https://www.rfc-editor.org/rfc/rfc9111.html#section-5.3
    expires_unix_timestamp: Option<u64>,
    /// The date from the `Last-Modified` header as specified in [RFC 9110 S8.8.2]
    /// in RFC 2822 format. It's used to compute a heuristic freshness lifetime for
    /// the response when other indicators are missing as per [RFC 9111 S4.2.2].
    ///
    /// [RFC 9110 S8.8.2]: https://www.rfc-editor.org/rfc/rfc9110#section-8.8.2
    /// [RFC 9111 S4.2.2]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.2
    last_modified_unix_timestamp: Option<u64>,
    /// The "entity tag" from the response as per [RFC 9110 S8.8.3], which is
    /// used in revalidation requests.
    ///
    /// [RFC 9110 S8.8.3]: https://www.rfc-editor.org/rfc/rfc9110#section-8.8.3
    etag: Option<ETag>,
}

impl From<&http::HeaderMap> for ResponseHeaders {
    fn from(headers: &http::HeaderMap) -> Self {
        Self {
            cc: headers.get_all("cache-control").iter().collect(),
            age_seconds: headers
                .get("age")
                .and_then(|header| parse_seconds(header.as_bytes())),
            date_unix_timestamp: headers
                .get("date")
                .and_then(|header| header.to_str().ok())
                .and_then(rfc2822_to_unix_timestamp),
            expires_unix_timestamp: headers
                .get("expires")
                .and_then(|header| header.to_str().ok())
                .and_then(rfc2822_to_unix_timestamp),
            last_modified_unix_timestamp: headers
                .get("last-modified")
                .and_then(|header| header.to_str().ok())
                .and_then(rfc2822_to_unix_timestamp),
            etag: headers
                .get("etag")
                .map(|header| ETag::parse(header.as_bytes())),
        }
    }
}

#[derive(Clone, Debug)]
struct ETag {
    /// The actual `ETag` validator value.
    ///
    /// This is received in the response, recorded as part of the cache policy
    /// and then sent back in a re-validation request. This is the "best"
    /// way for an HTTP server to return an HTTP 304 NOT MODIFIED status,
    /// indicating that our cached response is still fresh.
    value: Vec<u8>,
    /// When `weak` is true, this etag is considered a "weak" validator. In
    /// effect, it provides weaker semantics than a "strong" validator. As per
    /// [RFC 9110 S8.8.1]:
    ///
    /// "In contrast, a "weak validator" is representation metadata that might
    /// not change for every change to the representation data. This weakness
    /// might be due to limitations in how the value is calculated (e.g.,
    /// clock resolution), an inability to ensure uniqueness for all possible
    /// representations of the resource, or a desire of the resource owner to
    /// group representations by some self-determined set of equivalency rather
    /// than unique sequences of data."
    ///
    /// We don't currently support weak validation.
    ///
    /// [RFC 9110 S8.8.1]: https://www.rfc-editor.org/rfc/rfc9110#section-8.8.1-6
    weak: bool,
}

impl ETag {
    /// Parses an `ETag` from a header value.
    ///
    /// We are a little permissive here and allow arbitrary bytes,
    /// whereas [RFC 9110 S8.8.3] is a bit more restrictive.
    ///
    /// [RFC 9110 S8.8.3]: https://www.rfc-editor.org/rfc/rfc9110#section-8.8.3
    fn parse(header_value: &[u8]) -> Self {
        let (value, weak) = if header_value.starts_with(b"W/") {
            (&header_value[2..], true)
        } else {
            (header_value, false)
        };
        Self {
            value: value.to_vec(),
            weak,
        }
    }
}

/// Represents the `Vary` header on a cached response, as per [RFC 9110
/// S12.5.5] and [RFC 9111 S4.1].
///
/// This permits responses from the server to express things like, "only use
/// an existing cached response if the request from the client has the same
/// header values for the headers listed in `Vary` as in the original request."
///
/// [RFC 9110 S12.5.5]: https://www.rfc-editor.org/rfc/rfc9110#section-12.5.5
/// [RFC 9111 S4.1]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1
#[derive(Clone, Debug)]
struct Vary {
    fields: Vec<VaryField>,
}

impl Vary {
    /// Returns a `Vary` header value that will never match any request.
    fn always_fails_to_match() -> Self {
        Self {
            fields: vec![VaryField {
                name: "*".to_string(),
                value: vec![],
            }],
        }
    }

    fn from_request_response_headers(
        request: &http::HeaderMap,
        response: &http::HeaderMap,
    ) -> Self {
        // Parses the `Vary` header as per [RFC 9110 S12.5.5].
        //
        // [RFC 9110 S12.5.5]: https://www.rfc-editor.org/rfc/rfc9110#section-12.5.5
        let mut fields = vec![];
        for header in response.get_all("vary") {
            let Ok(csv) = header.to_str() else {
                continue;
            };
            for header_name in csv.split(',') {
                let header_name = header_name.trim().to_ascii_lowercase();
                // When we see a `*`, that means a failed match is an
                // inevitability, regardless of anything else. So just give up
                // and return a `Vary` that will never match.
                if header_name == "*" {
                    return Self::always_fails_to_match();
                }
                let value = request
                    .get(&header_name)
                    .map(|header| header.as_bytes().to_vec())
                    .unwrap_or_default();
                fields.push(VaryField {
                    name: header_name,
                    value,
                });
            }
        }
        Self { fields }
    }

    /// Returns true only when the `Vary` header on a cached response satisfies
    /// the request header values given, as per [RFC 9111 S4.1].
    ///
    /// [RFC 9111 S4.1]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1
    fn matches(&self, request_headers: &http::HeaderMap) -> bool {
        self.fields.iter().all(|field| {
            // A `*` anywhere means the match always fails.
            field.name != "*"
                && field.value.as_slice()
                    == request_headers
                        .get(field.name.as_str())
                        .map_or(&b""[..], http::HeaderValue::as_bytes)
        })
    }
}

/// A single field and value in a `Vary` header set by the response,
/// as per [RFC 9111 S4.1].
///
/// The `name` of the field comes from the `Vary` header in the response,
/// while the value of the field comes from the header with the same `name` in
/// the original request. These field and value pairs are then compared with
/// new incoming requests. If there is a mismatch, then the cached response
/// cannot be used without revalidation.
///
/// [RFC 9111 S4.1]: https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1
#[derive(Clone, Debug)]
struct VaryField {
    name: String,
    value: Vec<u8>,
}

fn unix_timestamp(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .expect("UNIX_EPOCH is as early as it gets")
        .as_secs()
}

fn rfc2822_to_unix_timestamp(value: &str) -> Option<u64> {
    rfc2822_to_datetime(value).and_then(|timestamp| u64::try_from(timestamp.as_second()).ok())
}

fn rfc2822_to_datetime(value: &str) -> Option<jiff::Timestamp> {
    jiff::fmt::rfc2822::DateTimeParser::new()
        .parse_timestamp(value)
        .ok()
}

fn unix_timestamp_to_header(seconds: u64) -> Option<HeaderValue> {
    unix_timestamp_to_rfc2822(seconds).and_then(|string| HeaderValue::from_str(&string).ok())
}

fn unix_timestamp_to_rfc2822(seconds: u64) -> Option<String> {
    use jiff::fmt::rfc2822::DateTimePrinter;

    unix_timestamp_to_datetime(seconds).and_then(|timestamp| {
        DateTimePrinter::new()
            .timestamp_to_rfc9110_string(&timestamp)
            .ok()
    })
}

fn unix_timestamp_to_datetime(seconds: u64) -> Option<jiff::Timestamp> {
    jiff::Timestamp::from_second(i64::try_from(seconds).ok()?).ok()
}

fn parse_seconds(value: &[u8]) -> Option<u64> {
    if !value.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_URI: &str = "https://example.com/data";

    fn policy(response: http::response::Builder) -> CachePolicy {
        let response = response.body(()).expect("test response is valid");
        CachePolicyBuilder::new(TEST_URI, &http::Method::GET, &http::HeaderMap::new())
            .build(response.status(), response.headers())
    }

    /// A server or proxy is free to send an arbitrarily large `Age` header, up
    /// to `u64::MAX`. Combined with the resident age of a cached response, the
    /// RFC 9111 S4.2.3 age computation must not overflow. Every term uses
    /// saturating arithmetic, so the age saturates to `Duration::from_secs`
    /// `(u64::MAX)` and the response is treated as stale rather than panicking
    /// (debug) or wrapping around to a bogus "fresh" age (release). This must
    /// remain stale even if the response's freshness lifetime also reaches
    /// `u64::MAX`.
    #[test]
    fn age_saturates_on_huge_age_header() {
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::AGE, u64::MAX.to_string())
            .header(http::header::CACHE_CONTROL, format!("max-age={}", u64::MAX))
            .body(())
            .expect("test response is valid");
        let policy = CachePolicyBuilder::new(TEST_URI, &http::Method::GET, &http::HeaderMap::new())
            .build(response.status(), response.headers());

        // `now` must be strictly after the response timestamp so that
        // `resident_age` is non-zero, which is the term that triggers the
        // overflow when added to a `u64::MAX`-derived initial age.
        let now = SystemTime::now() + Duration::from_secs(5);
        assert_eq!(policy.age(now), Duration::from_secs(u64::MAX));
        assert!(!policy.is_fresh(now, TEST_URI, &http::HeaderMap::new()));
    }

    #[test]
    fn fresh_response_is_reused() {
        let policy = policy(
            http::Response::builder()
                .status(http::StatusCode::OK)
                .header(http::header::CACHE_CONTROL, "private, max-age=60"),
        );

        assert!(policy.is_storable());
        let mut headers = http::HeaderMap::new();
        assert!(matches!(
            policy.before_request(TEST_URI, &http::Method::GET, &mut headers),
            BeforeRequest::Fresh
        ));
    }

    #[test]
    fn stale_response_adds_validator() {
        let policy = policy(
            http::Response::builder()
                .status(http::StatusCode::OK)
                .header(http::header::CACHE_CONTROL, "max-age=0")
                .header(http::header::ETAG, "\"version-1\""),
        );
        let mut headers = http::HeaderMap::new();

        assert!(matches!(
            policy.before_request(TEST_URI, &http::Method::GET, &mut headers),
            BeforeRequest::Stale(_)
        ));
        assert_eq!(headers[http::header::IF_NONE_MATCH], "\"version-1\"");
    }

    #[test]
    fn no_store_response_is_not_storable() {
        let policy = policy(
            http::Response::builder()
                .status(http::StatusCode::OK)
                .header(http::header::CACHE_CONTROL, "no-store"),
        );

        assert!(!policy.is_storable());
    }

    #[test]
    fn private_authenticated_response_is_storable() {
        let mut request_headers = http::HeaderMap::new();
        request_headers.insert(
            http::header::AUTHORIZATION,
            "Bearer secret".parse().expect("test header is valid"),
        );
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CACHE_CONTROL, "private, max-age=60")
            .body(())
            .expect("test response is valid");
        let policy = CachePolicyBuilder::new(TEST_URI, &http::Method::GET, &request_headers)
            .build(response.status(), response.headers());

        assert!(policy.is_storable());
    }

    #[test]
    fn vary_mismatch_requires_revalidation() {
        let mut original_headers = http::HeaderMap::new();
        original_headers.insert(
            http::header::ACCEPT,
            "application/json".parse().expect("test header is valid"),
        );
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CACHE_CONTROL, "max-age=60")
            .header(http::header::VARY, "accept")
            .body(())
            .expect("test response is valid");
        let policy = CachePolicyBuilder::new(TEST_URI, &http::Method::GET, &original_headers)
            .build(response.status(), response.headers());
        let mut next_headers = http::HeaderMap::new();
        next_headers.insert(
            http::header::ACCEPT,
            "text/plain".parse().expect("test header is valid"),
        );

        assert!(matches!(
            policy.before_request(TEST_URI, &http::Method::GET, &mut next_headers),
            BeforeRequest::Stale(_)
        ));
    }

    #[test]
    fn pre_epoch_http_date_is_ignored() {
        assert_eq!(
            rfc2822_to_unix_timestamp("Wed, 31 Dec 1969 23:59:59 GMT"),
            None
        );
    }
}
