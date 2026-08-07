package io.github.tobiasguta.copyasdirfuzz;

import java.util.List;

public final class DirFuzzCommandBuilderTest {
    public static void main(String[] args) {
        basicGet();
        authenticatedPost();
        preservesPayloadMarker();
        http2();
        powershellQuote();
        System.out.println("All DirFuzzCommandBuilder tests passed.");
    }

    private static void basicGet() {
        RequestSnapshot req = new RequestSnapshot(
                "GET", "https://example.com/admin", "HTTP/1.1",
                List.of(
                        new RequestSnapshot.HeaderValue("Host", "example.com"),
                        new RequestSnapshot.HeaderValue("Accept", "application/json")
                ), "");
        String actual = DirFuzzCommandBuilder.build(req, DirFuzzCommandBuilder.ShellStyle.POWERSHELL);
        assertContains(actual, "dirfuzz -u 'https://example.com/admin' -w 'wordlists/common.txt' -m 'GET'");
        assertContains(actual, "-H 'Accept: application/json'");
        assertNotContains(actual, "Host:");
    }

    private static void authenticatedPost() {
        RequestSnapshot req = new RequestSnapshot(
                "POST", "https://example.com/api/users", "HTTP/1.1",
                List.of(
                        new RequestSnapshot.HeaderValue("User-Agent", "Burp Test"),
                        new RequestSnapshot.HeaderValue("Cookie", "session=abc"),
                        new RequestSnapshot.HeaderValue("Authorization", "Bearer token"),
                        new RequestSnapshot.HeaderValue("Content-Type", "application/json"),
                        new RequestSnapshot.HeaderValue("Content-Length", "17")
                ), "{\"name\":\"alice\"}");
        String actual = DirFuzzCommandBuilder.build(req, DirFuzzCommandBuilder.ShellStyle.POWERSHELL);
        assertContains(actual, "-m 'POST'");
        assertContains(actual, "-ua 'Burp Test'");
        assertContains(actual, "-b 'session=abc'");
        assertContains(actual, "-H 'Authorization: Bearer token'");
        assertContains(actual, "-H 'Content-Type: application/json'");
        assertContains(actual, "-d '{\"name\":\"alice\"}'");
        assertNotContains(actual, "Content-Length");
    }

    private static void preservesPayloadMarker() {
        RequestSnapshot req = new RequestSnapshot(
                "POST", "https://example.com/api/users/{PAYLOAD}", "HTTP/1.1",
                List.of(new RequestSnapshot.HeaderValue("X-Test", "prefix-{PAYLOAD}")),
                "{\"id\":\"{PAYLOAD}\"}");
        String actual = DirFuzzCommandBuilder.build(req, DirFuzzCommandBuilder.ShellStyle.POWERSHELL);
        assertContains(actual, "https://example.com/api/users/{PAYLOAD}");
        assertContains(actual, "X-Test: prefix-{PAYLOAD}");
        assertContains(actual, "{\"id\":\"{PAYLOAD}\"}");
    }

    private static void http2() {
        RequestSnapshot req = new RequestSnapshot("GET", "https://example.com/", "HTTP/2", List.of(), "");
        String actual = DirFuzzCommandBuilder.build(req, DirFuzzCommandBuilder.ShellStyle.POWERSHELL);
        assertContains(actual, "--h2");
    }

    private static void powershellQuote() {
        RequestSnapshot req = new RequestSnapshot(
                "POST", "https://example.com/", "HTTP/1.1",
                List.of(new RequestSnapshot.HeaderValue("X-Name", "O'Reilly")),
                "it's fine");
        String actual = DirFuzzCommandBuilder.build(req, DirFuzzCommandBuilder.ShellStyle.POWERSHELL);
        assertContains(actual, "'X-Name: O''Reilly'");
        assertContains(actual, "'it''s fine'");
    }

    private static void assertContains(String actual, String expected) {
        if (!actual.contains(expected)) {
            throw new AssertionError("Expected to contain: " + expected + "\nActual: " + actual);
        }
    }

    private static void assertNotContains(String actual, String unexpected) {
        if (actual.contains(unexpected)) {
            throw new AssertionError("Expected not to contain: " + unexpected + "\nActual: " + actual);
        }
    }
}
