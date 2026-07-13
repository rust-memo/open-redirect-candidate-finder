package com.adminsec.redirectfinder;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.RowFilter;
import javax.swing.SpinnerNumberModel;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public final class FinderPanel extends JPanel {
    private final MontoyaApi api;
    private final FinderConfig config;
    private final FindingStore store;
    private final Runnable rescan;
    private final FindingTableModel model = new FindingTableModel();
    private final JTable table = new JTable(model);
    private final TableRowSorter<FindingTableModel> sorter = new TableRowSorter<>(model);
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JTextField search = new JTextField(24);
    private final JComboBox<String> severity = new JComboBox<>(new String[]{"All severities", "HIGH", "MEDIUM", "INFO"});
    private final JCheckBox scopeOnly = new JCheckBox("Target Scope only");
    private final JSpinner maxMb = new JSpinner(new SpinnerNumberModel(5, 1, 100, 1));
    private final JTextArea parameters = new JTextArea(8, 30);
    private final JTextArea sinks = new JTextArea(8, 30);
    private final JTextArea sources = new JTextArea(8, 30);

    public FinderPanel(MontoyaApi api, FinderConfig config, FindingStore store, Runnable rescan) {
        super(new BorderLayout());
        this.api = api;
        this.config = config;
        this.store = store;
        this.rescan = rescan;
        this.requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        buildUi();
        loadSettings();
        store.listener(ignored -> refresh());
    }

    private void buildUi() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Findings", findingsPanel());
        tabs.addTab("Settings", settingsPanel());
        add(tabs, BorderLayout.CENTER);
        api.userInterface().applyThemeToComponent(this);
    }

    private JPanel findingsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        JPanel filters = new JPanel(new FlowLayout(FlowLayout.LEFT));
        filters.add(new JLabel("Search:")); filters.add(search); filters.add(severity);
        JButton rescanButton = new JButton("Rescan History");
        rescanButton.addActionListener(e -> rescan.run());
        JButton clear = new JButton("Clear results");
        clear.addActionListener(e -> { store.clear(); refresh(); });
        filters.add(rescanButton); filters.add(clear);

        table.setRowSorter(sorter);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths = {65, 80, 130, 150, 420, 210, 150};
        for (int i = 0; i < widths.length; i++) table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        table.getSelectionModel().addListSelectionListener(e -> showSelection());
        search.getDocument().addDocumentListener((SimpleDocumentListener) e -> applyFilter());
        severity.addActionListener(e -> applyFilter());

        JSplitPane editors = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.uiComponent(), responseEditor.uiComponent());
        editors.setResizeWeight(0.5);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), editors);
        split.setResizeWeight(0.55);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addButton(actions, "Send to Repeater", this::sendToRepeater);
        addButton(actions, "Mark reviewed", () -> setStatus(Finding.ReviewStatus.REVIEWED));
        addButton(actions, "False positive", () -> setStatus(Finding.ReviewStatus.FALSE_POSITIVE));
        addButton(actions, "Needs review", () -> setStatus(Finding.ReviewStatus.NEEDS_REVIEW));
        addButton(actions, "Ignore host", this::ignoreHost);
        addButton(actions, "Ignore marker", this::ignoreMarker);
        addButton(actions, "Export JSON", () -> export(false));
        addButton(actions, "Export CSV", () -> export(true));

        panel.add(filters, BorderLayout.NORTH);
        panel.add(split, BorderLayout.CENTER);
        panel.add(actions, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel settingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 6, 6, 6); c.anchor = GridBagConstraints.NORTHWEST; c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 0; c.gridy = 0; panel.add(scopeOnly, c);
        c.gridy++; panel.add(new JLabel("Maximum text response size (MB):"), c);
        c.gridx = 1; panel.add(maxMb, c);
        c.gridx = 0; c.gridy++; panel.add(new JLabel("Redirect parameters (one per line):"), c);
        c.gridx = 1; panel.add(new JLabel("Client-side sinks:"), c);
        c.gridx = 2; panel.add(new JLabel("Client-side sources:"), c);
        c.gridx = 0; c.gridy++; c.weightx = 1; c.weighty = 1; c.fill = GridBagConstraints.BOTH; panel.add(new JScrollPane(parameters), c);
        c.gridx = 1; panel.add(new JScrollPane(sinks), c);
        c.gridx = 2; panel.add(new JScrollPane(sources), c);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addButton(buttons, "Apply and rescan", this::applySettings);
        addButton(buttons, "Restore defaults", this::restoreDefaults);
        c.gridx = 0; c.gridy++; c.gridwidth = 3; c.weighty = 0; c.fill = GridBagConstraints.HORIZONTAL; panel.add(buttons, c);
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        return panel;
    }

    private void loadSettings() {
        scopeOnly.setSelected(config.scopeOnly());
        maxMb.setValue(Math.max(1, config.maxResponseBytes() / (1024 * 1024)));
        parameters.setText(FinderConfig.serialize(config.parameters()));
        sinks.setText(FinderConfig.serialize(config.sinks()));
        sources.setText(FinderConfig.serialize(config.sources()));
    }

    private void applySettings() {
        config.scopeOnly(scopeOnly.isSelected());
        config.maxResponseBytes((Integer) maxMb.getValue() * 1024 * 1024);
        config.parameters(FinderConfig.normalizedSet(parameters.getText()));
        config.sinks(FinderConfig.normalizedSet(sinks.getText()));
        config.sources(FinderConfig.normalizedSet(sources.getText()));
        config.save(api.persistence().preferences());
        store.clear(); rescan.run();
    }

    private void restoreDefaults() {
        parameters.setText(FinderConfig.serialize(FinderConfig.DEFAULT_PARAMETERS));
        sinks.setText(FinderConfig.serialize(FinderConfig.DEFAULT_SINKS));
        sources.setText(FinderConfig.serialize(FinderConfig.DEFAULT_SOURCES));
        scopeOnly.setSelected(true); maxMb.setValue(5);
        config.ignoredHosts().clear();
        config.ignoredMarkers().clear();
    }

    private void addButton(JPanel panel, String label, Runnable action) {
        JButton button = new JButton(label); button.addActionListener(e -> action.run()); panel.add(button);
    }

    private Finding selected() {
        int view = table.getSelectedRow();
        return view < 0 ? null : model.get(sorter.convertRowIndexToModel(view));
    }

    private void showSelection() {
        Finding finding = selected();
        if (finding == null) return;
        requestEditor.setRequest(finding.request());
        if (finding.response() != null) responseEditor.setResponse(finding.response());
        if (!finding.marker().isBlank()) responseEditor.setSearchExpression(finding.marker());
    }

    private void sendToRepeater() {
        Finding f = selected();
        if (f != null) api.repeater().sendToRepeater(f.request(), "Redirect candidate - " + f.host());
    }

    private void setStatus(Finding.ReviewStatus status) {
        Finding f = selected(); if (f != null) store.setStatus(f, status);
    }

    private void ignoreHost() {
        Finding f = selected(); if (f == null) return;
        config.ignoredHosts().add(f.host().toLowerCase(Locale.ROOT));
        config.save(api.persistence().preferences());
        store.removeIf(item -> item.host().equalsIgnoreCase(f.host()));
    }

    private void ignoreMarker() {
        Finding f = selected(); if (f == null || f.marker().isBlank()) return;
        config.ignoredMarkers().add(f.marker().toLowerCase(Locale.ROOT));
        config.save(api.persistence().preferences());
        store.removeIf(item -> item.marker().equalsIgnoreCase(f.marker()));
    }

    private void applyFilter() {
        String q = search.getText().trim(); String sev = (String) severity.getSelectedItem();
        sorter.setRowFilter(new RowFilter<>() {
            public boolean include(Entry<? extends FindingTableModel, ? extends Integer> entry) {
                Finding f = model.get(entry.getIdentifier());
                boolean severityOk = "All severities".equals(sev) || f.severity().name().equals(sev);
                String haystack = f.request().url() + " " + f.title() + " " + f.evidence() + " " + f.kind();
                return severityOk && (q.isEmpty() || haystack.toLowerCase(Locale.ROOT).contains(q.toLowerCase(Locale.ROOT)));
            }
        });
    }

    private void refresh() { model.replace(store.snapshot()); }

    private void export(boolean csv) {
        JFileChooser chooser = new JFileChooser();
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path path = chooser.getSelectedFile().toPath();
        try {
            Files.writeString(path, csv ? Exporter.csv(store.snapshot()) : Exporter.json(store.snapshot()), StandardCharsets.UTF_8);
        } catch (IOException error) {
            JOptionPane.showMessageDialog(this, error.getMessage(), "Export failed", JOptionPane.ERROR_MESSAGE);
        }
    }

    private static final class FindingTableModel extends AbstractTableModel {
        private final String[] columns = {"Severity", "Method", "Kind", "Title", "URL", "Evidence", "Status"};
        private List<Finding> rows = new ArrayList<>();
        public void replace(List<Finding> value) { rows = new ArrayList<>(value); fireTableDataChanged(); }
        public Finding get(int row) { return rows.get(row); }
        public int getRowCount() { return rows.size(); }
        public int getColumnCount() { return columns.length; }
        public String getColumnName(int column) { return columns[column]; }
        public Object getValueAt(int row, int column) {
            Finding f = rows.get(row);
            return switch (column) {
                case 0 -> f.severity(); case 1 -> f.request().method(); case 2 -> f.kind();
                case 3 -> f.title(); case 4 -> f.request().url(); case 5 -> f.evidence(); default -> f.reviewStatus();
            };
        }
    }

    @FunctionalInterface private interface SimpleDocumentListener extends javax.swing.event.DocumentListener {
        void update(javax.swing.event.DocumentEvent e);
        default void insertUpdate(javax.swing.event.DocumentEvent e) { update(e); }
        default void removeUpdate(javax.swing.event.DocumentEvent e) { update(e); }
        default void changedUpdate(javax.swing.event.DocumentEvent e) { update(e); }
    }
}
