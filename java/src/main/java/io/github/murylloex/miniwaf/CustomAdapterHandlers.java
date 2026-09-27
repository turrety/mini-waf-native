package io.github.murylloex.miniwaf;

import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.ToIntBiFunction;

/**
 * The request / response mappers {@link MiniWaf#createAdapter} turns into an
 * adapter. Each setter is named after the handler it sets.
 *
 * <p>Required: {@code getMethod}, {@code getUrl}, {@code getIp},
 * {@code getHeaders}, {@code getRawBody}, {@code setResponseHeader} and
 * {@code drop}. The others default as in Rust: the path is the URL up to
 * {@code ?}, the protocol {@code "http"}, the port 0, a header is looked up
 * in {@code getHeaders}, the query is parsed from the URL, cookies from the
 * {@code Cookie} header, no files, and removing a header does nothing.
 */
public final class CustomAdapterHandlers<TRequest, TResponse> {

    /** Sets a response header. */
    @FunctionalInterface
    public interface SetResponseHeader<TResponse> {
        void set(TResponse response, String name, String value);
    }

    /** Ends the request with a block response. */
    @FunctionalInterface
    public interface Drop<TRequest, TResponse> {
        void drop(
            TRequest request,
            TResponse response,
            int statusCode,
            String body
        );
    }

    final String name;
    Function<TRequest, String> getMethod;
    Function<TRequest, String> getUrl;
    Function<TRequest, String> getPath;
    Function<TRequest, String> getIp;
    Function<TRequest, String> getProtocol;
    ToIntBiFunction<TRequest, TResponse> getLocalPort;
    BiFunction<TRequest, String, Optional<String>> getHeader;
    Function<TRequest, HeaderMap> getHeaders;
    Function<TRequest, QueryMap> getQuery;
    Function<TRequest, CookieMap> getCookies;
    Function<TRequest, RawBody> getRawBody;
    Function<TRequest, FilesBag> getFiles;
    SetResponseHeader<TResponse> setResponseHeader;
    BiConsumer<TResponse, String> removeResponseHeader;
    Drop<TRequest, TResponse> drop;

    /** Start describing an integration named {@code name} (shown in logs). */
    public CustomAdapterHandlers(String name) {
        this.name = name;
    }

    /** HTTP method. */
    public CustomAdapterHandlers<TRequest, TResponse> getMethod(
        Function<TRequest, String> handler
    ) {
        this.getMethod = handler;
        return this;
    }

    /** Full request target including the query string ({@code /a/b?x=1}). */
    public CustomAdapterHandlers<TRequest, TResponse> getUrl(
        Function<TRequest, String> handler
    ) {
        this.getUrl = handler;
        return this;
    }

    /** Path as it arrived on the wire (still percent-encoded). */
    public CustomAdapterHandlers<TRequest, TResponse> getPath(
        Function<TRequest, String> handler
    ) {
        this.getPath = handler;
        return this;
    }

    /**
     * Raw client address; it is normalized for you. Behind a proxy, derive it
     * from {@code X-Forwarded-For} with {@link MiniWaf#pickClientIpFromXff}.
     */
    public CustomAdapterHandlers<TRequest, TResponse> getIp(
        Function<TRequest, String> handler
    ) {
        this.getIp = handler;
        return this;
    }

    /** {@code http} / {@code https}. */
    public CustomAdapterHandlers<TRequest, TResponse> getProtocol(
        Function<TRequest, String> handler
    ) {
        this.getProtocol = handler;
        return this;
    }

    /** Port the server accepted the connection on. */
    public CustomAdapterHandlers<TRequest, TResponse> getLocalPort(
        ToIntBiFunction<TRequest, TResponse> handler
    ) {
        this.getLocalPort = handler;
        return this;
    }

    /** One header by lowercase name. */
    public CustomAdapterHandlers<TRequest, TResponse> getHeader(
        BiFunction<TRequest, String, Optional<String>> handler
    ) {
        this.getHeader = handler;
        return this;
    }

    /** Every header. Lowercase the names. */
    public CustomAdapterHandlers<TRequest, TResponse> getHeaders(
        Function<TRequest, HeaderMap> handler
    ) {
        this.getHeaders = handler;
        return this;
    }

    /** Parsed query parameters, when the framework already parses them. */
    public CustomAdapterHandlers<TRequest, TResponse> getQuery(
        Function<TRequest, QueryMap> handler
    ) {
        this.getQuery = handler;
        return this;
    }

    /** Parsed cookies, when the framework already parses them. */
    public CustomAdapterHandlers<TRequest, TResponse> getCookies(
        Function<TRequest, CookieMap> handler
    ) {
        this.getCookies = handler;
        return this;
    }

    /** The buffered request body. */
    public CustomAdapterHandlers<TRequest, TResponse> getRawBody(
        Function<TRequest, RawBody> handler
    ) {
        this.getRawBody = handler;
        return this;
    }

    /** Uploaded files (only their names are inspected). */
    public CustomAdapterHandlers<TRequest, TResponse> getFiles(
        Function<TRequest, FilesBag> handler
    ) {
        this.getFiles = handler;
        return this;
    }

    /** Set a response header (used for {@code X-RateLimit-*}). */
    public CustomAdapterHandlers<TRequest, TResponse> setResponseHeader(
        SetResponseHeader<TResponse> handler
    ) {
        this.setResponseHeader = handler;
        return this;
    }

    /** Remove a response header. */
    public CustomAdapterHandlers<TRequest, TResponse> removeResponseHeader(
        BiConsumer<TResponse, String> handler
    ) {
        this.removeResponseHeader = handler;
        return this;
    }

    /** End the request with a block response. */
    public CustomAdapterHandlers<TRequest, TResponse> drop(
        Drop<TRequest, TResponse> handler
    ) {
        this.drop = handler;
        return this;
    }
}
