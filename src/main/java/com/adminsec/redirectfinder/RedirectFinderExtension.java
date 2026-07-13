package com.adminsec.redirectfinder;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import burp.api.montoya.persistence.PersistedObject;

import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public final class RedirectFinderExtension implements BurpExtension {
    private static final String NAME = "Open Redirect Candidate Finder";
    private static final String NOTE_TAG = "[Redirect Finder]";
    private MontoyaApi api;
    private FinderConfig config;
    private PassiveAnalyzer analyzer;
    private FindingStore store;
    private ExecutorService scanner;
    private final AtomicBoolean scanning = new AtomicBoolean();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName(NAME);
        config = FinderConfig.load(api.persistence().preferences());
        analyzer = new PassiveAnalyzer(config);
        PersistedObject projectData;
        try {
            projectData = api.persistence().extensionData();
        } catch (RuntimeException unavailable) {
            projectData = null;
            api.logging().logToOutput("Project persistence unavailable; review statuses will be kept in memory.");
        }
        store = new FindingStore(projectData);
        scanner = Executors.newSingleThreadExecutor(r -> {
            Thread thread = new Thread(r, "redirect-finder-history");
            thread.setDaemon(true);
            return thread;
        });

        FinderPanel panel = new FinderPanel(api, config, store, this::scanHistory);
        api.userInterface().registerSuiteTab("Redirect Candidates", panel);
        api.proxy().registerResponseHandler(new LiveResponseHandler());
        api.extension().registerUnloadingHandler(() -> scanner.shutdownNow());

        api.logging().logToOutput(NAME + " 2.0 loaded (passive, Target Scope only by default).");
        scanHistory();
    }

    private void scanHistory() {
        if (!scanning.compareAndSet(false, true)) {
            api.logging().logToOutput("History scan already running.");
            return;
        }
        scanner.submit(() -> {
            int scanned = 0;
            try {
                List<ProxyHttpRequestResponse> history = api.proxy().history(item -> {
                    HttpRequest request = item.finalRequest();
                    return request != null && (!config.scopeOnly() || request.isInScope());
                });
                for (ProxyHttpRequestResponse item : history) {
                    if (Thread.currentThread().isInterrupted()) return;
                    HttpRequest request = item.finalRequest();
                    HttpResponse response = item.hasResponse() ? item.response() : null;
                    List<Finding> findings = analyzer.analyze(request, response);
                    publish(findings, item.annotations());
                    scanned++;
                }
                api.logging().logToOutput("History scan finished: " + scanned + " items, " + store.snapshot().size() + " unique findings.");
            } catch (RuntimeException error) {
                api.logging().logToError("History scan failed", error);
            } finally {
                scanning.set(false);
            }
        });
    }

    private void publish(List<Finding> findings, Annotations annotations) {
        if (findings.isEmpty()) return;
        store.addAll(findings);

        Finding.Severity highest = findings.stream().map(Finding::severity)
                .min(Comparator.comparingInt(this::severityRank)).orElse(Finding.Severity.INFO);
        String summary = NOTE_TAG + " " + highest + " - " + findings.stream()
                .map(Finding::title).distinct().limit(4).reduce((a, b) -> a + "; " + b).orElse("candidate");
        if (!annotations.hasNotes() || !annotations.notes().contains(summary)) {
            annotations.setNotes(annotations.hasNotes() && !annotations.notes().isBlank()
                    ? annotations.notes() + " | " + summary : summary);
        }
        if (!annotations.hasHighlightColor() || annotations.highlightColor() == HighlightColor.NONE) {
            annotations.setHighlightColor(color(highest));
        }
    }

    private int severityRank(Finding.Severity severity) {
        return switch (severity) { case HIGH -> 0; case MEDIUM -> 1; case INFO -> 2; };
    }

    private HighlightColor color(Finding.Severity severity) {
        return switch (severity) { case HIGH -> HighlightColor.RED; case MEDIUM -> HighlightColor.ORANGE; case INFO -> HighlightColor.CYAN; };
    }

    private final class LiveResponseHandler implements ProxyResponseHandler {
        @Override
        public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse response) {
            try {
                List<Finding> findings = analyzer.analyze(response.request(), response);
                publish(findings, response.annotations());
            } catch (RuntimeException error) {
                api.logging().logToError("Live passive analysis failed", error);
            }
            return ProxyResponseReceivedAction.continueWith(response, response.annotations());
        }

        @Override
        public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse response) {
            return ProxyResponseToBeSentAction.continueWith(response, response.annotations());
        }
    }
}
