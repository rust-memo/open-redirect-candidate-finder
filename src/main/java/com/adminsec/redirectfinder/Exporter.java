package com.adminsec.redirectfinder;

import java.util.List;

public final class Exporter {
    private Exporter() {}

    public static String csv(List<Finding> findings) {
        StringBuilder out = new StringBuilder("severity,kind,method,url,title,evidence,status\n");
        for (Finding f : findings) {
            out.append(csv(f.severity().name())).append(',').append(csv(f.kind().name())).append(',')
                    .append(csv(f.request().method())).append(',').append(csv(f.request().url())).append(',')
                    .append(csv(f.title())).append(',').append(csv(redact(f.evidence()))).append(',')
                    .append(csv(f.reviewStatus().name())).append('\n');
        }
        return out.toString();
    }

    public static String json(List<Finding> findings) {
        StringBuilder out = new StringBuilder("[\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            out.append("  {\"severity\":\"").append(json(f.severity().name()))
                    .append("\",\"kind\":\"").append(json(f.kind().name()))
                    .append("\",\"method\":\"").append(json(f.request().method()))
                    .append("\",\"url\":\"").append(json(f.request().url()))
                    .append("\",\"title\":\"").append(json(f.title()))
                    .append("\",\"evidence\":\"").append(json(redact(f.evidence())))
                    .append("\",\"status\":\"").append(json(f.reviewStatus().name())).append("\"}");
            if (i + 1 < findings.size()) out.append(',');
            out.append('\n');
        }
        return out.append("]\n").toString();
    }

    private static String redact(String value) {
        return value.replaceAll("(?i)(authorization|cookie|set-cookie)\\s*[:=]\\s*[^|,;\\r\\n]+", "$1: [REDACTED]");
    }
    private static String csv(String value) {
        String safe = value == null ? "" : value;
        if (!safe.isEmpty() && "=+-@".indexOf(safe.charAt(0)) >= 0) safe = "'" + safe;
        return "\"" + safe.replace("\"", "\"\"") + "\"";
    }
    private static String json(String value) {
        StringBuilder escaped = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\' -> escaped.append("\\\\");
                case '"' -> escaped.append("\\\"");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (c < 0x20) escaped.append(String.format("\\u%04x", (int) c));
                    else escaped.append(c);
                }
            }
        }
        return escaped.toString();
    }
}
