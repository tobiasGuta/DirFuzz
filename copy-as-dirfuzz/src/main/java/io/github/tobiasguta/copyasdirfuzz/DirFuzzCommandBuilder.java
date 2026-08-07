package io.github.tobiasguta.copyasdirfuzz;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

final class DirFuzzCommandBuilder {
    static final String DEFAULT_BINARY = "dirfuzz";
    static final String DEFAULT_WORDLIST = "wordlists/common.txt";

    private static final Set<String> GENERATED_HEADERS = Set.of(
            "host", "content-length"
    );

    private DirFuzzCommandBuilder() {}

    static String build(RequestSnapshot request, ShellStyle shell) {
        if (request == null) {
            throw new IllegalArgumentException("request is required");
        }
        if (request.url() == null || request.url().isBlank()) {
            throw new IllegalArgumentException("request URL is empty");
        }
        if (request.method() == null || request.method().isBlank()) {
            throw new IllegalArgumentException("request method is empty");
        }

        List<String> args = new ArrayList<>();
        args.add(DEFAULT_BINARY);
        addOption(args, "-u", request.url());
        addOption(args, "-w", DEFAULT_WORDLIST);

        // Always force the selected Burp method. Leaving -m unset makes DirFuzz
        // use its HEAD/GET optimization, which would not faithfully reflect the request.
        addOption(args, "-m", request.method().toUpperCase(Locale.ROOT));

        if (request.httpVersion() != null && request.httpVersion().equalsIgnoreCase("HTTP/2")) {
            args.add("--h2");
        }

        String userAgent = null;
        String cookie = null;
        for (RequestSnapshot.HeaderValue header : request.headers()) {
            if (header == null || header.name() == null) {
                continue;
            }
            String name = header.name().trim();
            String value = header.value() == null ? "" : header.value();
            if (name.isEmpty() || name.startsWith(":")) {
                continue;
            }

            String lower = name.toLowerCase(Locale.ROOT);
            if (GENERATED_HEADERS.contains(lower)) {
                continue;
            }

            if (lower.equals("user-agent")) {
                userAgent = value;
            } else if (lower.equals("cookie")) {
                cookie = value;
            } else {
                addOption(args, "-H", name + ": " + value);
            }
        }

        if (userAgent != null) {
            addOption(args, "-ua", userAgent);
        }
        if (cookie != null) {
            addOption(args, "-b", cookie);
        }
        if (request.body() != null && !request.body().isEmpty()) {
            addOption(args, "-d", request.body());
        }

        return shell.join(args);
    }

    private static void addOption(List<String> args, String flag, String value) {
        args.add(flag);
        args.add(value == null ? "" : value);
    }

    enum ShellStyle {
        POWERSHELL {
            @Override
            String quote(String value) {
                return "'" + value.replace("'", "''") + "'";
            }
        },
        POSIX {
            @Override
            String quote(String value) {
                return "'" + value.replace("'", "'\"'\"'") + "'";
            }
        };

        abstract String quote(String value);

        String join(List<String> args) {
            Set<String> flagTokens = Set.of("-u", "-w", "-m", "--h2", "-H", "-ua", "-b", "-d");
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < args.size(); i++) {
                if (i > 0) {
                    out.append(' ');
                }
                String arg = args.get(i);
                if (i == 0 || flagTokens.contains(arg)) {
                    out.append(arg);
                } else {
                    if (arg.indexOf('\0') >= 0) {
                        throw new IllegalArgumentException("Request data contains a NUL byte, which cannot be represented in a command-line argument");
                    }
                    out.append(quote(arg));
                }
            }
            return out.toString();
        }

        static ShellStyle current() {
            String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
            return os.contains("win") ? POWERSHELL : POSIX;
        }
    }
}
