package com.adminsec.redirectfinder;

import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URLDecoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

public final class PassiveAnalyzer {
    private static final int FLOW_DISTANCE = 1200;
    private static final Pattern SOURCE_MAP = Pattern.compile("(?i)[#@]\\s*sourceMappingURL\\s*=\\s*([^\\s*]+)");
    private final FinderConfig config;

    public PassiveAnalyzer(FinderConfig config) { this.config = config; }

    public List<Finding> analyze(HttpRequest request, HttpResponse response) {
        List<Finding> findings = new ArrayList<>();
        if (request == null || (config.scopeOnly() && !request.isInScope())) return findings;
        if (config.ignoredHosts().contains(request.httpService().host().toLowerCase(Locale.ROOT))) return findings;

        List<ParsedHttpParameter> candidates = redirectParameters(request);
        analyzeParameters(request, response, candidates, findings);
        analyzeLocation(request, response, candidates, findings);
        analyzeBody(request, response, findings);
        return findings;
    }

    private List<ParsedHttpParameter> redirectParameters(HttpRequest request) {
        return request.parameters().stream()
                .filter(p -> p.type() != HttpParameterType.COOKIE)
                .filter(p -> config.parameters().contains(p.name().toLowerCase(Locale.ROOT)))
                .filter(p -> !config.ignoredMarkers().contains(p.name().toLowerCase(Locale.ROOT)))
                .toList();
    }

    private void analyzeParameters(HttpRequest request, HttpResponse response,
                                   List<ParsedHttpParameter> parameters, List<Finding> out) {
        for (ParsedHttpParameter parameter : parameters) {
            String value = parameter.value() == null ? "" : parameter.value();
            boolean urlLike = looksLikeDestination(decodeRepeated(value));
            out.add(new Finding(request, response,
                    urlLike ? Finding.Severity.MEDIUM : Finding.Severity.INFO,
                    Finding.Kind.REDIRECT_PARAMETER,
                    "Suspicious redirect parameter: " + parameter.name(),
                    parameter.type() + " | " + parameter.name() + "=" + truncate(value, 500),
                    parameter.name().toLowerCase(Locale.ROOT)));
        }
    }

    private void analyzeLocation(HttpRequest request, HttpResponse response,
                                 List<ParsedHttpParameter> parameters, List<Finding> out) {
        if (response == null || response.statusCode() < 300 || response.statusCode() > 399 || !response.hasHeader("Location")) return;
        String location = response.headerValue("Location");
        if (location == null || location.isBlank()) return;
        for (ParsedHttpParameter parameter : parameters) {
            String decoded = decodeRepeated(parameter.value());
            boolean reflected = !decoded.isBlank() && normalize(location).contains(normalize(decoded));
            out.add(new Finding(request, response,
                    reflected ? Finding.Severity.HIGH : Finding.Severity.MEDIUM,
                    Finding.Kind.HTTP_REDIRECT,
                    reflected ? "Input appears in HTTP Location" : "3xx Location with redirect parameter",
                    "HTTP " + response.statusCode() + " Location: " + truncate(location, 700)
                            + " | " + parameter.name() + "=" + truncate(parameter.value(), 300),
                    parameter.name().toLowerCase(Locale.ROOT)));
        }
    }

    private void analyzeBody(HttpRequest request, HttpResponse response, List<Finding> out) {
        if (response == null || response.body().length() == 0 || response.body().length() > config.maxResponseBytes()) return;
        if (!isTextual(request, response)) return;
        String body = responseText(response);
        if (body == null || body.isEmpty()) return;
        String lower = body.toLowerCase(Locale.ROOT);
        List<Hit> sinks = hits(lower, config.sinks());
        List<Hit> sources = hits(lower, config.sources());

        HitPair pair = closestPair(sources, sinks);
        if (pair != null && pair.distance() <= FLOW_DISTANCE) {
            String evidence = pair.source().marker() + " -> " + pair.sink().marker() + " | "
                    + snippet(body, Math.min(pair.source().index(), pair.sink().index()),
                    Math.max(pair.source().index(), pair.sink().index()) + pair.sink().marker().length());
            out.add(new Finding(request, response, Finding.Severity.HIGH, Finding.Kind.CLIENT_SIDE_FLOW,
                    "Nearby client-side source and navigation sink", evidence, pair.sink().marker()));
        } else {
            for (Hit sink : sinks) {
                out.add(new Finding(request, response, Finding.Severity.MEDIUM, Finding.Kind.CLIENT_SIDE_SINK,
                        "Client-side navigation sink", sink.marker() + " | " + snippet(body, sink.index(), sink.index() + sink.marker().length()), sink.marker()));
            }
            for (Hit source : sources) {
                out.add(new Finding(request, response, Finding.Severity.INFO, Finding.Kind.CLIENT_SIDE_SOURCE,
                        "Client-side input source", source.marker() + " | " + snippet(body, source.index(), source.index() + source.marker().length()), source.marker()));
            }
        }

        Matcher sourceMap = SOURCE_MAP.matcher(body);
        if (sourceMap.find()) {
            out.add(new Finding(request, response, Finding.Severity.INFO, Finding.Kind.SOURCE_MAP,
                    "Source map reference (not fetched)", truncate(sourceMap.group(), 500), "sourcemappingurl"));
        }
    }

    private boolean isTextual(HttpRequest request, HttpResponse response) {
        MimeType mime = response.mimeType();
        String value = mime == null ? "" : mime.toString().toLowerCase(Locale.ROOT);
        String extension = request.fileExtension() == null ? "" : request.fileExtension().toLowerCase(Locale.ROOT).replaceFirst("^\\.", "");
        return value.contains("script") || value.contains("html") || value.contains("json")
                || value.contains("xml") || value.contains("text")
                || Set.of("js", "mjs", "cjs", "map", "json", "html", "htm", "jsx", "ts", "tsx", "vue").contains(extension);
    }

    private String responseText(HttpResponse response) {
        String header = response.hasHeader("Content-Encoding") ? response.headerValue("Content-Encoding") : null;
        String encoding = header == null ? "identity" : header.trim().toLowerCase(Locale.ROOT);
        if (encoding.isBlank() || encoding.equals("identity")) return response.bodyToString();
        if (!encoding.equals("gzip") && !encoding.equals("x-gzip") && !encoding.equals("deflate")) return null;
        try (ByteArrayInputStream input = new ByteArrayInputStream(response.body().getBytes());
             var decoded = encoding.contains("gzip") ? new GZIPInputStream(input) : new InflaterInputStream(input);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int total = 0;
            for (int read; (read = decoded.read(buffer)) != -1;) {
                total += read;
                if (total > config.maxResponseBytes()) return null;
                output.write(buffer, 0, read);
            }
            return output.toString(StandardCharsets.UTF_8);
        } catch (IOException malformedEncoding) {
            return null;
        }
    }

    private List<Hit> hits(String lowerBody, Set<String> markers) {
        List<Hit> hits = new ArrayList<>();
        for (String marker : markers) {
            if (config.ignoredMarkers().contains(marker)) continue;
            int index = lowerBody.indexOf(marker);
            if (index >= 0) hits.add(new Hit(marker, index));
        }
        return hits;
    }

    private static HitPair closestPair(List<Hit> sources, List<Hit> sinks) {
        HitPair best = null;
        for (Hit source : sources) for (Hit sink : sinks) {
            HitPair pair = new HitPair(source, sink, Math.abs(source.index() - sink.index()));
            if (best == null || pair.distance() < best.distance()) best = pair;
        }
        return best;
    }

    public static String decodeRepeated(String input) {
        String value = input == null ? "" : input;
        for (int i = 0; i < 3; i++) {
            try {
                String decoded = URLDecoder.decode(value, StandardCharsets.UTF_8);
                if (decoded.equals(value)) break;
                value = decoded;
            } catch (IllegalArgumentException malformed) { break; }
        }
        return value;
    }

    public static boolean looksLikeDestination(String value) {
        String lower = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        return lower.startsWith("http://") || lower.startsWith("https://")
                || lower.startsWith("//") || lower.startsWith("\\\\")
                || lower.startsWith("/\\") || lower.startsWith("\\/");
    }

    private static String normalize(String value) {
        return decodeRepeated(value).trim().replace("\\/", "/").toLowerCase(Locale.ROOT);
    }

    private static String snippet(String body, int start, int end) {
        int from = Math.max(0, start - 100);
        int to = Math.min(body.length(), end + 140);
        return truncate(body.substring(from, to).replaceAll("\\s+", " "), 600);
    }

    private static String truncate(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max) + "...";
    }

    private record Hit(String marker, int index) {}
    private record HitPair(Hit source, Hit sink, int distance) {}
}
