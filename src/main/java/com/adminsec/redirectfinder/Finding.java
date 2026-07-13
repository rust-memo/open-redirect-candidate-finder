package com.adminsec.redirectfinder;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;

public final class Finding {
    public enum Severity { HIGH, MEDIUM, INFO }
    public enum Kind { HTTP_REDIRECT, REDIRECT_PARAMETER, CLIENT_SIDE_FLOW, CLIENT_SIDE_SINK, CLIENT_SIDE_SOURCE, SOURCE_MAP }
    public enum ReviewStatus { NEEDS_REVIEW, REVIEWED, FALSE_POSITIVE }

    private final String fingerprint;
    private final Instant discoveredAt;
    private final HttpRequest request;
    private final HttpResponse response;
    private final Severity severity;
    private final Kind kind;
    private final String title;
    private final String evidence;
    private final String marker;
    private volatile ReviewStatus reviewStatus;

    public Finding(HttpRequest request, HttpResponse response, Severity severity, Kind kind,
                   String title, String evidence, String marker) {
        this.request = Objects.requireNonNull(request);
        this.response = response;
        this.severity = Objects.requireNonNull(severity);
        this.kind = Objects.requireNonNull(kind);
        this.title = Objects.requireNonNull(title);
        this.evidence = evidence == null ? "" : evidence;
        this.marker = marker == null ? "" : marker;
        this.discoveredAt = Instant.now();
        this.reviewStatus = ReviewStatus.NEEDS_REVIEW;
        this.fingerprint = sha256(request.method() + "\n" + request.url() + "\n" + kind + "\n" + title + "\n" + this.evidence);
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    public String fingerprint() { return fingerprint; }
    public Instant discoveredAt() { return discoveredAt; }
    public HttpRequest request() { return request; }
    public HttpResponse response() { return response; }
    public Severity severity() { return severity; }
    public Kind kind() { return kind; }
    public String title() { return title; }
    public String evidence() { return evidence; }
    public String marker() { return marker; }
    public ReviewStatus reviewStatus() { return reviewStatus; }
    public void reviewStatus(ReviewStatus value) { reviewStatus = Objects.requireNonNull(value); }
    public String host() { return request.httpService().host(); }
}

