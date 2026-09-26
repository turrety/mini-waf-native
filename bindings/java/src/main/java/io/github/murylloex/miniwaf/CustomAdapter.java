package io.github.murylloex.miniwaf;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.function.BiConsumer;

/**
 * The adapter {@link MiniWaf#createAdapter} builds. It is thread-safe when
 * its handlers are.
 */
public final class CustomAdapter<TRequest, TResponse> extends NativeResource {

    final CustomAdapterHandlers<TRequest, TResponse> handlers;

    CustomAdapter(CustomAdapterHandlers<TRequest, TResponse> handlers) {
        super(create(handlers), Api::customAdapterFree);
        this.handlers = handlers;
    }

    public String name() {
        return handlers.name;
    }

    private static MemorySegment create(CustomAdapterHandlers<?, ?> handlers) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment name = Native.text(arena, handlers.name);
            MemorySegment nativeHandlers = Api.customAdapterHandlersNew(
                name,
                Native.length(name)
            );
            try {
                register(nativeHandlers, handlers);
                MemorySegment error = arena.allocate(Native.POINTER);
                MemorySegment adapter = Api.createAdapter(
                    nativeHandlers,
                    error
                );
                if (adapter.equals(MemorySegment.NULL)) {
                    throw new AdapterBuildError(
                        Native.takeString(error.get(Native.POINTER, 0))
                    );
                }
                return adapter;
            } finally {
                Api.customAdapterHandlersFree(nativeHandlers);
            }
        }
    }

    /** Register the callback of every handler that is set. */
    private static void register(
        MemorySegment target,
        CustomAdapterHandlers<?, ?> h
    ) {
        set(
            target,
            h.getMethod,
            "get_method",
            Api::customAdapterHandlersGetMethod
        );
        set(target, h.getUrl, "get_url", Api::customAdapterHandlersGetUrl);
        set(target, h.getPath, "get_path", Api::customAdapterHandlersGetPath);
        set(target, h.getIp, "get_ip", Api::customAdapterHandlersGetIp);
        set(
            target,
            h.getProtocol,
            "get_protocol",
            Api::customAdapterHandlersGetProtocol
        );
        set(
            target,
            h.getLocalPort,
            "get_local_port",
            Api::customAdapterHandlersGetLocalPort
        );
        set(
            target,
            h.getHeader,
            "get_header",
            Api::customAdapterHandlersGetHeader
        );
        set(
            target,
            h.getHeaders,
            "get_headers",
            Api::customAdapterHandlersGetHeaders
        );
        set(
            target,
            h.getQuery,
            "get_query",
            Api::customAdapterHandlersGetQuery
        );
        set(
            target,
            h.getCookies,
            "get_cookies",
            Api::customAdapterHandlersGetCookies
        );
        set(
            target,
            h.getRawBody,
            "get_raw_body",
            Api::customAdapterHandlersGetRawBody
        );
        set(
            target,
            h.getFiles,
            "get_files",
            Api::customAdapterHandlersGetFiles
        );
        set(
            target,
            h.setResponseHeader,
            "set_response_header",
            Api::customAdapterHandlersSetResponseHeader
        );
        set(
            target,
            h.removeResponseHeader,
            "remove_response_header",
            Api::customAdapterHandlersRemoveResponseHeader
        );
        set(target, h.drop, "drop", Api::customAdapterHandlersDrop);
    }

    private static void set(
        MemorySegment target,
        Object handler,
        String name,
        BiConsumer<MemorySegment, MemorySegment> setter
    ) {
        if (handler != null) {
            setter.accept(target, Upcalls.ADAPTER.get(name));
        }
    }
}
