package com.adminsec.redirectfinder;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.io.ByteArrayOutputStream;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class PassiveAnalyzerTest {
    @Test
    void detectsEncodedExternalDestination() {
        Fixture f = fixture("https://app.test/login?next=https%3A%2F%2Fevil.test", "next",
                "https%3A%2F%2Fevil.test", null, (short) 200, null);
        List<Finding> findings = f.analyzer.analyze(f.request, f.response);
        assertTrue(findings.stream().anyMatch(x -> x.kind() == Finding.Kind.REDIRECT_PARAMETER
                && x.severity() == Finding.Severity.MEDIUM));
    }

    @Test
    void elevatesReflectedLocation() {
        Fixture f = fixture("https://app.test/login?next=https%3A%2F%2Fevil.test", "next",
                "https%3A%2F%2Fevil.test", "https://evil.test", (short) 302, null);
        List<Finding> findings = f.analyzer.analyze(f.request, f.response);
        assertTrue(findings.stream().anyMatch(x -> x.kind() == Finding.Kind.HTTP_REDIRECT
                && x.severity() == Finding.Severity.HIGH));
    }

    @Test
    void correlatesNearbyClientSourceAndSink() {
        String body = "const target = new URLSearchParams(location.search).get('next'); window.location.assign(target);";
        Fixture f = fixture("https://app.test/app.js", null, null, null, (short) 200, body);
        List<Finding> findings = f.analyzer.analyze(f.request, f.response);
        assertTrue(findings.stream().anyMatch(x -> x.kind() == Finding.Kind.CLIENT_SIDE_FLOW
                && x.severity() == Finding.Severity.HIGH));
    }

    @Test
    void ignoresOutOfScopeTraffic() {
        Fixture f = fixture("https://outside.test/?next=https://evil.test", "next", "https://evil.test", null, (short) 200, null);
        when(f.request.isInScope()).thenReturn(false);
        assertTrue(f.analyzer.analyze(f.request, f.response).isEmpty());
    }

    @Test
    void decodingIsBoundedAndMalformedInputIsSafe() {
        assertEquals("https://x.test", PassiveAnalyzer.decodeRepeated("https%253A%252F%252Fx.test"));
        assertDoesNotThrow(() -> PassiveAnalyzer.decodeRepeated("%E0%A4%A"));
    }

    @Test
    void scansGzipJavaScriptWithinConfiguredLimit() throws Exception {
        String script = "const x = location.hash; location.replace(x);";
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(output)) { gzip.write(script.getBytes()); }
        Fixture f = fixture("https://app.test/app.js", null, null, null, (short) 200, null);
        ByteArray bytes = mock(ByteArray.class);
        when(bytes.length()).thenReturn(output.size());
        when(bytes.getBytes()).thenReturn(output.toByteArray());
        when(f.response.body()).thenReturn(bytes);
        when(f.response.hasHeader("Content-Encoding")).thenReturn(true);
        when(f.response.headerValue("Content-Encoding")).thenReturn("gzip");
        assertTrue(f.analyzer.analyze(f.request, f.response).stream()
                .anyMatch(x -> x.kind() == Finding.Kind.CLIENT_SIDE_FLOW));
    }

    private static Fixture fixture(String url, String parameterName, String parameterValue,
                                   String location, short status, String body) {
        FinderConfig config = new FinderConfig();
        PassiveAnalyzer analyzer = new PassiveAnalyzer(config);
        HttpRequest request = mock(HttpRequest.class);
        HttpResponse response = mock(HttpResponse.class);
        HttpService service = mock(HttpService.class);
        when(request.isInScope()).thenReturn(true);
        when(request.url()).thenReturn(url);
        when(request.method()).thenReturn("GET");
        when(request.httpService()).thenReturn(service);
        when(service.host()).thenReturn("app.test");
        when(request.fileExtension()).thenReturn(url.endsWith(".js") ? "js" : "");
        if (parameterName == null) {
            when(request.parameters()).thenReturn(List.of());
        } else {
            ParsedHttpParameter parameter = mock(ParsedHttpParameter.class);
            when(parameter.name()).thenReturn(parameterName);
            when(parameter.value()).thenReturn(parameterValue);
            when(parameter.type()).thenReturn(HttpParameterType.URL);
            when(request.parameters()).thenReturn(List.of(parameter));
        }
        when(response.statusCode()).thenReturn(status);
        when(response.hasHeader("Location")).thenReturn(location != null);
        when(response.headerValue("Location")).thenReturn(location);
        String responseBody = body == null ? "" : body;
        ByteArray bytes = mock(ByteArray.class);
        when(bytes.length()).thenReturn(responseBody.length());
        when(response.body()).thenReturn(bytes);
        when(response.bodyToString()).thenReturn(responseBody);
        when(response.mimeType()).thenReturn(body == null ? MimeType.PLAIN_TEXT : MimeType.SCRIPT);
        return new Fixture(analyzer, request, response);
    }

    private record Fixture(PassiveAnalyzer analyzer, HttpRequest request, HttpResponse response) {}
}
