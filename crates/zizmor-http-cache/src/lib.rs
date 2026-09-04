/*!
A somewhat simplistic implementation of HTTP cache semantics.

This implementation was guided by the following things:

* RFCs 9110 and 9111.
* The `http-cache-semantics` crate. (The implementation here is completely
  different, but the source of `http-cache-semantics` helped guide the
  implementation here and understanding of HTTP caching.)
* A desire to keep cache policy independent of HTTP clients, async runtimes
  and storage implementations.

# Flow

While one has to read the relevant RFCs to get a full understanding of HTTP
caching, doing so is... difficult to say the least. It is at the very least
not quick to do because the semantics are scattered all over the place. But, I
think we can do a quick overview here.

Let's start with the obvious. HTTP caching exists to avoid network requests,
and, if a request is unavoidable, bandwidth. The central actor in HTTP
caching is the `Cache-Control` header, which can exist on *both* requests and
responses. The value of this header is a list of directives that control caching
behavior. They can outright disable it (`no-store`), force cache invalidation
(`no-cache`) or even permit the cache to return responses that are explicitly
stale (`max-stale`).

The main thing that typically drives cache interactions is `max-age`. When set
on a response, this means that the server is willing to let clients hold on to
a response for up to the amount of time in `max-age` before the client must ask
the server for a fresh response. In our case, the main utility of `max-age` is
two fold:

* GitHub sets finite freshness lifetimes on some API responses. As long as a
  cached response is younger than this, zizmor can avoid talking to GitHub.
* Other assets can be effectively immutable. Servers will typically set a
  very high `max-age`, which means clients will almost never need to ask the
  server for permission to reuse the cached response.

When a cached response exceeds the `max-age` configured on a response, then
we call that response stale. Generally speaking, we won't return responses
from the cache that are known to be stale. This can be overridden in the
request by adding a `max-stale` cache-control directive. When a response is
stale, we don't necessarily need to give up completely. It is at this point
that we can send something called a re-validation request.

A re-validation request includes with it some metadata (usually an "entity tag"
or `etag` for short) that was on the cached response (which is now stale).
When we send this request, the server can compare it with its most up-to-date
version of the resource. If its entity tag matches the one we gave it (among
other possible criteria), then the server can skip returning the body and
instead just return a small HTTP 304 NOT MODIFIED response. When we get this
type of response, it's the server telling us that our cached response which we
*thought* was stale is no longer stale. It's fresh again and we needn't get a
new copy. We will need to update our stored [`CachePolicy`] though, since the
HTTP 304 NOT MODIFIED response we got might include updated metadata relevant
to the behavior of caching (like a new `Age` header).

# Scope

In general, the cache semantics implemented below are targeted toward a
private client cache. This constraint results in a modest simplification in
what we need to support. That is, we don't need to cache the entirety of the
request's or response's headers (like what `http-cache-semantics` does).
Instead, we only need to cache the data necessary to *make decisions* about
HTTP caching.

One example of this is the `Vary` response header. This requires checking the
headers listed in a cached response have the same value in the original
request and the new request. If the new request has different values for those
headers (as specified in the cached response) than what was in the original
request, then the new request cannot use our cached response. Normally, this
would seemingly require storing all of the original request's headers. But we
only store the headers listed in the response.

Also, since we aren't a proxy, there are a host of proxy-specific rules for
managing headers and data that we needn't care about.

This crate only determines whether responses may be stored and reused. It
intentionally does not provide storage or an HTTP-client adapter, leaving
consumers free to choose both.

# Additional reading

* Short introduction to `Cache-Control`: <https://csswizardry.com/2019/03/cache-control-for-civilians/>
* Caching best practices: <https://jakearchibald.com/2016/caching-best-practices/>
* Overview of HTTP caching: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching>
* MDN docs for `Cache-Control`: <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control>
* The 1997 RFC for HTTP 1.1: <https://www.rfc-editor.org/rfc/rfc2068#section-13>
* The 1999 update to HTTP 1.1: <https://www.rfc-editor.org/rfc/rfc2616.html#section-13>
* The "stale content" cache-control extension: <https://httpwg.org/specs/rfc5861.html>
* HTTP 1.1 caching (superseded by RFC 9111): <https://httpwg.org/specs/rfc7234.html>
* The "immutable" cache-control extension: <https://httpwg.org/specs/rfc8246.html>
* HTTP semantics (If-None-Match, etc.): <https://www.rfc-editor.org/rfc/rfc9110#section-8.8.3>
* HTTP caching (obsoletes RFC 7234): <https://www.rfc-editor.org/rfc/rfc9111.html>

The policy is derived from uv's implementation. See the crate README and
`LICENSE-UV` for source and license details.
*/

mod control;
mod policy;

pub use policy::{AfterResponse, BeforeRequest, CachePolicy, CachePolicyBuilder};
