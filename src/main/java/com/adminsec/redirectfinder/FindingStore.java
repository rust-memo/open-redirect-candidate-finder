package com.adminsec.redirectfinder;

import burp.api.montoya.persistence.PersistedObject;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Predicate;

public final class FindingStore {
    private static final String REVIEWED_KEY = "redirectFinder.reviewed";
    private static final String FALSE_POSITIVE_KEY = "redirectFinder.falsePositives";
    private final Map<String, Finding> findings = new LinkedHashMap<>();
    private final Set<String> reviewed = ConcurrentHashMap.newKeySet();
    private final Set<String> falsePositives = ConcurrentHashMap.newKeySet();
    private final PersistedObject projectData;
    private volatile Consumer<List<Finding>> listener = ignored -> {};

    public FindingStore(PersistedObject projectData) {
        this.projectData = projectData;
        loadSet(REVIEWED_KEY, reviewed);
        loadSet(FALSE_POSITIVE_KEY, falsePositives);
    }

    private void loadSet(String key, Set<String> target) {
        if (projectData == null) return;
        try {
            String value = projectData.getString(key);
            if (value != null) value.lines().filter(s -> !s.isBlank()).forEach(target::add);
        } catch (RuntimeException ignored) {
            // Project persistence is unavailable in some Burp editions/modes.
        }
    }

    public void listener(Consumer<List<Finding>> listener) { this.listener = listener; }

    public void addAll(Collection<Finding> additions) {
        List<Finding> inserted = new ArrayList<>();
        synchronized (findings) {
            for (Finding finding : additions) {
                if (findings.containsKey(finding.fingerprint())) continue;
                if (reviewed.contains(finding.fingerprint())) finding.reviewStatus(Finding.ReviewStatus.REVIEWED);
                if (falsePositives.contains(finding.fingerprint())) finding.reviewStatus(Finding.ReviewStatus.FALSE_POSITIVE);
                findings.put(finding.fingerprint(), finding);
                inserted.add(finding);
            }
        }
        if (!inserted.isEmpty()) SwingUtilities.invokeLater(() -> listener.accept(inserted));
    }

    public List<Finding> snapshot() {
        synchronized (findings) { return new ArrayList<>(findings.values()); }
    }

    public void clear() {
        synchronized (findings) { findings.clear(); }
        SwingUtilities.invokeLater(() -> listener.accept(List.of()));
    }

    public void removeIf(Predicate<Finding> predicate) {
        synchronized (findings) { findings.values().removeIf(predicate); }
        SwingUtilities.invokeLater(() -> listener.accept(List.of()));
    }

    public void setStatus(Finding finding, Finding.ReviewStatus status) {
        finding.reviewStatus(status);
        reviewed.remove(finding.fingerprint());
        falsePositives.remove(finding.fingerprint());
        if (status == Finding.ReviewStatus.REVIEWED) reviewed.add(finding.fingerprint());
        if (status == Finding.ReviewStatus.FALSE_POSITIVE) falsePositives.add(finding.fingerprint());
        persist();
        SwingUtilities.invokeLater(() -> listener.accept(List.of()));
    }

    private void persist() {
        if (projectData == null) return;
        try {
            projectData.setString(REVIEWED_KEY, String.join("\n", reviewed));
            projectData.setString(FALSE_POSITIVE_KEY, String.join("\n", falsePositives));
        } catch (RuntimeException ignored) {
            // In-memory status still works when project persistence is unavailable.
        }
    }
}
