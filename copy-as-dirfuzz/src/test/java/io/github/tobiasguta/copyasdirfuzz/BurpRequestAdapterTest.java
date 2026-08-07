package io.github.tobiasguta.copyasdirfuzz;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.List;

public final class BurpRequestAdapterTest {
    public static void main(String[] args) {
        HttpRequest request = new FakeRequest(
                "GET",
                "https://example.com/api/%7BPAYLOAD%7D?x=1",
                "HTTP/1.1",
                List.of(new FakeHeader("Host", "example.com")),
                "",
                "GET /api/{PAYLOAD}?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        );
        String url = BurpRequestAdapter.rawTargetUrl(request);
        if (!url.equals("https://example.com/api/{PAYLOAD}?x=1")) {
            throw new AssertionError("raw marker was not preserved: " + url);
        }
        System.out.println("BurpRequestAdapter raw-target test passed.");
    }

    record FakeHeader(String name, String value) implements HttpHeader {}

    static final class FakeBytes implements ByteArray {
        private final byte[] bytes;
        FakeBytes(String value) { this.bytes = value.getBytes(StandardCharsets.ISO_8859_1); }
        @Override public byte[] getBytes() { return bytes.clone(); }
    }

    record FakeRequest(
            String method,
            String url,
            String httpVersion,
            List<HttpHeader> headers,
            String bodyToString,
            String raw) implements HttpRequest {
        @Override public ByteArray toByteArray() { return new FakeBytes(raw); }
    }
}
