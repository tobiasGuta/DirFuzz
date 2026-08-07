package io.github.tobiasguta.copyasdirfuzz;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

final class BurpRequestAdapter {
    private BurpRequestAdapter() {}

    static RequestSnapshot from(HttpRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("No HTTP request is available");
        }

        String url = rawTargetUrl(request);
        List<RequestSnapshot.HeaderValue> headers = new ArrayList<>();
        for (HttpHeader header : request.headers()) {
            headers.add(new RequestSnapshot.HeaderValue(header.name(), header.value()));
        }

        return new RequestSnapshot(
                request.method(),
                url,
                request.httpVersion(),
                List.copyOf(headers),
                request.bodyToString()
        );
    }

    /**
     * Montoya's request.url() is normally enough, but the raw request target is
     * preferred so a literal DirFuzz {PAYLOAD} marker typed in Repeater is not
     * normalized or percent-encoded by a URI formatter before we copy it.
     */
    static String rawTargetUrl(HttpRequest request) {
        String raw = new String(request.toByteArray().getBytes(), StandardCharsets.ISO_8859_1);
        int eol = raw.indexOf("\r\n");
        if (eol < 0) {
            eol = raw.indexOf('\n');
        }
        if (eol > 0) {
            String requestLine = raw.substring(0, eol);
            int firstSpace = requestLine.indexOf(' ');
            int lastSpace = requestLine.lastIndexOf(' ');
            if (firstSpace > 0 && lastSpace > firstSpace) {
                String target = requestLine.substring(firstSpace + 1, lastSpace);
                if (target.startsWith("http://") || target.startsWith("https://")) {
                    return target;
                }
                if (target.startsWith("/")) {
                    try {
                        URI parsed = new URI(request.url());
                        if (parsed.getScheme() != null && parsed.getRawAuthority() != null) {
                            return parsed.getScheme() + "://" + parsed.getRawAuthority() + target;
                        }
                    } catch (URISyntaxException ignored) {
                        // Fall back to Montoya's parsed URL below.
                    }
                }
            }
        }
        return request.url();
    }
}
