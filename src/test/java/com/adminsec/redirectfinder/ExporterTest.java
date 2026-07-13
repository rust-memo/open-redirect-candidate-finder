package com.adminsec.redirectfinder;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ExporterTest {
    @Test
    void protectsCsvCellsAndEscapesJsonControlCharacters() {
        HttpRequest request = mock(HttpRequest.class);
        HttpService service = mock(HttpService.class);
        when(request.method()).thenReturn("GET");
        when(request.url()).thenReturn("=HYPERLINK(\"https://example.test\")");
        when(request.httpService()).thenReturn(service);
        when(service.host()).thenReturn("example.test");

        Finding finding = new Finding(request, null, Finding.Severity.INFO,
                Finding.Kind.REDIRECT_PARAMETER, "tab\tvalue", "marker", "next");

        String csv = Exporter.csv(List.of(finding));
        String json = Exporter.json(List.of(finding));
        assertTrue(csv.contains("\"'=HYPERLINK"));
        assertFalse(json.contains("tab\tvalue"));
        assertTrue(json.contains("tab\\tvalue"));
    }
}
