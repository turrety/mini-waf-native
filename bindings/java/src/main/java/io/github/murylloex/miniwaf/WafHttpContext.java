package io.github.murylloex.miniwaf;

import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * Framework-agnostic HTTP view consumed by the WAF engine
 * ({@link MiniWafInstance#handle}).
 *
 * <p>The engine resolves every rule field exclusively through these
 * methods, so an implementation returning the wrong value for
 * {@link #getIp()} silently breaks every {@code ip} rule and rate-limit
 * bucket. Most applications use {@link MiniWaf#createAdapter} instead.
 */
public interface WafHttpContext {
    /** Name of the integration, for logs. */
    String framework();

    String getMethod();

    /** Full request target, including the query string. */
    String getUrl();

    /**
     * Path without the query string, as it arrived on the wire (still
     * percent-encoded).
     */
    String getPath();

    /** Normalized client IP (see {@link MiniWaf#normalizeClientIp}). */
    String getIp();

    String getProtocol();

    int getLocalPort();

    /** One header by (lowercase) name. */
    Optional<String> getHeader(String name);

    HeaderMap getHeaders();

    QueryMap getQuery();

    CookieMap getCookies();

    String getRawBody();

    List<UploadedFile> getFiles();

    void setResponseHeader(String name, String value);

    void removeResponseHeader(String name);

    boolean isBlocked();

    /**
     * Ends the request with a block response. Defaults: status 403, body
     * "Forbidden".
     */
    void drop(OptionalInt statusCode, Optional<String> body);
}
