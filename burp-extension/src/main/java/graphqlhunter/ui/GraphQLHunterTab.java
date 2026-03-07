package graphqlhunter.ui;

import graphqlhunter.GraphQLHunterJson;
import graphqlhunter.GraphQLHunterLogger;
import graphqlhunter.GraphQLHunterModels.ExtensionState;
import graphqlhunter.GraphQLHunterModels.Finding;
import graphqlhunter.GraphQLHunterModels.ScanProfile;
import graphqlhunter.GraphQLHunterModels.ScanRequest;
import graphqlhunter.GraphQLHunterModels.ScanSettings;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;

public final class GraphQLHunterTab extends JPanel
{
    public interface GraphQLHunterActions
    {
        ExtensionState currentState();

        void saveState(ExtensionState state);

        void runScan(ScanRequest request, ScanSettings settings, Consumer<List<Finding>> onSuccess, Consumer<Throwable> onError);
    }

    private final GraphQLHunterActions actions;
    private final GraphQLHunterLogger logger;
    private final JTextField sourceField = new JTextField();
    private final JTextField urlField = new JTextField();
    private final JTextField methodField = new JTextField();
    private final JTextField delayField = new JTextField();
    private final JComboBox<ScanProfile> profileCombo = new JComboBox<>(ScanProfile.values());
    private final JCheckBox safeModeCheck = new JCheckBox("Safe mode");
    private final JTextArea queryArea = new JTextArea();
    private final JTextArea variablesArea = new JTextArea();
    private final JTextArea headersArea = new JTextArea();
    private final JTextArea detailsArea = new JTextArea();
    private final JTextArea logArea = new JTextArea();
    private final JLabel statusLabel = new JLabel("Ready.");
    private final JButton scanButton = new JButton("Run Focused GraphQL Checks");
    private final JButton saveButton = new JButton("Save Request");
    private final JButton clearButton = new JButton("Clear Findings");
    private final FindingTableModel findingTableModel = new FindingTableModel();
    private final JTable findingsTable = new JTable(findingTableModel);

    public GraphQLHunterTab(GraphQLHunterActions actions, GraphQLHunterLogger logger)
    {
        super(new BorderLayout(10, 10));
        this.actions = actions;
        this.logger = logger;
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        sourceField.setEditable(false);
        methodField.setColumns(8);
        delayField.setColumns(6);
        sourceField.setColumns(18);
        queryArea.setLineWrap(true);
        queryArea.setWrapStyleWord(true);
        variablesArea.setLineWrap(true);
        variablesArea.setWrapStyleWord(true);
        headersArea.setLineWrap(true);
        headersArea.setWrapStyleWord(true);
        detailsArea.setEditable(false);
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        logArea.setEditable(false);
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);

        logger.addListener(line -> SwingUtilities.invokeLater(() ->
        {
            logArea.append(line + System.lineSeparator());
            logArea.setCaretPosition(logArea.getDocument().getLength());
        }));

        findingsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        findingsTable.getSelectionModel().addListSelectionListener(event ->
        {
            if (event.getValueIsAdjusting())
            {
                return;
            }
            Finding selected = findingTableModel.get(findingsTable.getSelectedRow());
            detailsArea.setText(selected == null ? "" : selected.details());
        });

        scanButton.addActionListener(event -> runScan());
        saveButton.addActionListener(event -> saveState());
        clearButton.addActionListener(event ->
        {
            findingTableModel.setRows(List.of());
            detailsArea.setText("");
            statusLabel.setText("Cleared findings.");
        });

        add(buildTopPanel(), BorderLayout.NORTH);
        add(buildMainSplitPane(), BorderLayout.CENTER);
        add(buildLogPanel(), BorderLayout.SOUTH);

        load(actions.currentState());
    }

    public void importRequest(ScanRequest request)
    {
        if (request == null)
        {
            return;
        }
        sourceField.setText(request.source);
        urlField.setText(request.url);
        methodField.setText(request.method);
        queryArea.setText(request.query == null ? "" : request.query);
        variablesArea.setText(renderVariables(request.variables));
        headersArea.setText(renderHeaders(request.headers));
        statusLabel.setText("Imported GraphQL request from Burp.");
        saveState();
    }

    private JPanel buildTopPanel()
    {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0;

        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("Source"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 0.3;
        panel.add(sourceField, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0;
        panel.add(new JLabel("Method"), gbc);
        gbc.gridx = 3;
        gbc.weightx = 0.1;
        panel.add(methodField, gbc);

        gbc.gridx = 4;
        gbc.weightx = 0;
        panel.add(new JLabel("Profile"), gbc);
        gbc.gridx = 5;
        gbc.weightx = 0.15;
        panel.add(profileCombo, gbc);

        gbc.gridx = 6;
        gbc.weightx = 0;
        panel.add(safeModeCheck, gbc);

        gbc.gridx = 7;
        panel.add(new JLabel("Delay"), gbc);

        gbc.gridx = 8;
        gbc.weightx = 0.1;
        panel.add(delayField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0;
        panel.add(new JLabel("URL"), gbc);
        gbc.gridx = 1;
        gbc.gridwidth = 8;
        gbc.weightx = 1.0;
        panel.add(urlField, gbc);
        gbc.gridwidth = 1;

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        buttonRow.add(scanButton);
        buttonRow.add(saveButton);
        buttonRow.add(clearButton);
        buttonRow.add(statusLabel);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 9;
        gbc.weightx = 1.0;
        panel.add(buttonRow, gbc);

        return panel;
    }

    private JSplitPane buildMainSplitPane()
    {
        JSplitPane outerSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        outerSplit.setResizeWeight(0.45);
        outerSplit.setTopComponent(buildEditorPanel());
        outerSplit.setBottomComponent(buildFindingsSplitPane());
        return outerSplit;
    }

    private JPanel buildEditorPanel()
    {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0;
        gbc.weighty = 0.5;

        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(labeledScroll("GraphQL Query", queryArea, 220), gbc);

        gbc.gridx = 1;
        panel.add(labeledScroll("Variables (JSON)", variablesArea, 220), gbc);

        gbc.gridx = 2;
        panel.add(labeledScroll("Headers", headersArea, 220), gbc);

        return panel;
    }

    private JSplitPane buildFindingsSplitPane()
    {
        JScrollPane findingsScroll = new JScrollPane(findingsTable);
        findingsScroll.setPreferredSize(new Dimension(520, 240));
        JScrollPane detailsScroll = new JScrollPane(detailsArea);
        detailsScroll.setPreferredSize(new Dimension(520, 240));

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, findingsScroll, detailsScroll);
        splitPane.setResizeWeight(0.45);
        return splitPane;
    }

    private JPanel buildLogPanel()
    {
        JPanel panel = new JPanel(new BorderLayout(4, 4));
        panel.add(new JLabel("Extension Log"), BorderLayout.NORTH);
        JScrollPane scrollPane = new JScrollPane(logArea);
        scrollPane.setPreferredSize(new Dimension(500, 140));
        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JScrollPane labeledScroll(String title, JTextArea area, int preferredHeight)
    {
        area.setBorder(BorderFactory.createTitledBorder(title));
        JScrollPane scrollPane = new JScrollPane(area);
        scrollPane.setPreferredSize(new Dimension(320, preferredHeight));
        return scrollPane;
    }

    private void load(ExtensionState state)
    {
        if (state == null)
        {
            return;
        }
        if (state.lastRequest != null)
        {
            importRequest(state.lastRequest);
        }
        try
        {
            String profileName = state.scanSettings != null && state.scanSettings.profileName != null && !state.scanSettings.profileName.isBlank()
                ? state.scanSettings.profileName
                : state.scanProfile;
            profileCombo.setSelectedItem(ScanProfile.valueOf(profileName));
        }
        catch (IllegalArgumentException ignored)
        {
            profileCombo.setSelectedItem(ScanProfile.STANDARD);
        }
        if (state.scanSettings != null)
        {
            safeModeCheck.setSelected(state.scanSettings.safeMode);
            delayField.setText(state.scanSettings.delaySeconds == null ? "" : String.valueOf(state.scanSettings.delaySeconds));
        }
        statusLabel.setText("Ready.");
    }

    private void saveState()
    {
        ExtensionState current = actions.currentState();
        ExtensionState state = new ExtensionState();
        state.lastRequest = buildRequestFromInputs();
        state.scanSettings = buildScanSettingsFromInputs();
        state.scanProfile = state.scanSettings.profileName;
        state.authSettings = current == null || current.authSettings == null ? new graphqlhunter.GraphQLHunterModels.AuthSettings() : current.authSettings.copy();
        actions.saveState(state);
        statusLabel.setText("Saved current request state.");
    }

    private void runScan()
    {
        ScanRequest request = buildRequestFromInputs();
        if (request.url == null || request.url.isBlank() || request.query == null || request.query.isBlank())
        {
            statusLabel.setText("URL and GraphQL query are required.");
            return;
        }

        ScanSettings settings = buildScanSettingsFromInputs();
        saveState();
        statusLabel.setText("Running focused checks...");
        scanButton.setEnabled(false);
        detailsArea.setText("");
        findingTableModel.setRows(List.of());

        actions.runScan(request, settings, findings ->
        {
            findingTableModel.setRows(findings);
            statusLabel.setText("Completed " + findings.size() + " finding(s).");
            scanButton.setEnabled(true);
            if (!findings.isEmpty())
            {
                findingsTable.getSelectionModel().setSelectionInterval(0, 0);
            }
        }, throwable ->
        {
            statusLabel.setText("Scan failed: " + throwable.getMessage());
            scanButton.setEnabled(true);
        });
    }

    private ScanRequest buildRequestFromInputs()
    {
        ScanRequest request = new ScanRequest();
        request.source = sourceField.getText().isBlank() ? "manual" : sourceField.getText().trim();
        request.url = urlField.getText().trim();
        request.method = methodField.getText().isBlank() ? "POST" : methodField.getText().trim().toUpperCase(Locale.ROOT);
        request.query = queryArea.getText();
        request.operationName = "";
        request.headers = parseHeaders(headersArea.getText());
        request.variables = parseVariables(variablesArea.getText());
        return request;
    }

    private ScanSettings buildScanSettingsFromInputs()
    {
        ScanSettings settings = new ScanSettings();
        settings.profileName = ((ScanProfile) profileCombo.getSelectedItem()).name();
        settings.safeMode = safeModeCheck.isSelected();
        if (!delayField.getText().isBlank())
        {
            try
            {
                settings.delaySeconds = Double.parseDouble(delayField.getText().trim());
            }
            catch (NumberFormatException exception)
            {
                logger.warn("Delay must be numeric; using profile default.");
                settings.delaySeconds = null;
            }
        }
        return settings;
    }

    private Object parseVariables(String text)
    {
        if (text == null || text.isBlank())
        {
            return new LinkedHashMap<String, Object>();
        }
        try
        {
            return GraphQLHunterJson.mapper().readValue(text, Object.class);
        }
        catch (Exception exception)
        {
            logger.warn("Variables are not valid JSON; sending an empty variables object.");
            return new LinkedHashMap<String, Object>();
        }
    }

    private String renderVariables(Object variables)
    {
        if (variables == null)
        {
            return "{}";
        }
        return GraphQLHunterJson.write(variables);
    }

    private Map<String, String> parseHeaders(String text)
    {
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        if (text == null || text.isBlank())
        {
            return headers;
        }
        for (String line : text.split("\\R"))
        {
            if (line == null || line.isBlank() || !line.contains(":"))
            {
                continue;
            }
            String[] parts = line.split(":", 2);
            headers.put(parts[0].trim(), parts[1].trim());
        }
        return headers;
    }

    private String renderHeaders(Map<String, String> headers)
    {
        StringBuilder builder = new StringBuilder();
        headers.forEach((key, value) -> builder.append(key).append(": ").append(value).append(System.lineSeparator()));
        return builder.toString().trim();
    }

    private static final class FindingTableModel extends AbstractTableModel
    {
        private final String[] columns = {"Severity", "Status", "Scanner", "Title"};
        private final List<Finding> rows = new ArrayList<>();

        public void setRows(List<Finding> findings)
        {
            rows.clear();
            rows.addAll(findings);
            fireTableDataChanged();
        }

        public Finding get(int row)
        {
            return row >= 0 && row < rows.size() ? rows.get(row) : null;
        }

        @Override
        public int getRowCount()
        {
            return rows.size();
        }

        @Override
        public int getColumnCount()
        {
            return columns.length;
        }

        @Override
        public String getColumnName(int column)
        {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex)
        {
            Finding finding = rows.get(rowIndex);
            return switch (columnIndex)
            {
                case 0 -> finding.severity;
                case 1 -> finding.status;
                case 2 -> finding.scanner;
                case 3 -> finding.title;
                default -> "";
            };
        }
    }
}
