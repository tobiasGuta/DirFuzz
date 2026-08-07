package io.github.tobiasguta.copyasdirfuzz;

import java.util.List;

record RequestSnapshot(
        String method,
        String url,
        String httpVersion,
        List<HeaderValue> headers,
        String body) {

    record HeaderValue(String name, String value) {}
}
