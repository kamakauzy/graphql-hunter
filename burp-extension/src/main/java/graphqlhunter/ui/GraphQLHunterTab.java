package graphqlhunter.ui;

import graphqlhunter.GraphQLHunterJson;
import graphqlhunter.GraphQLHunterLogger;
import graphqlhunter.GraphQLHunterModels.ExtensionState;
import graphqlhunter.GraphQLHunterModels.Finding;
import graphqlhunter.GraphQLHunterModels.AuthSettings;
import graphqlhunter.GraphQLHunterModels.ScanProfile;
import graphqlhunter.GraphQLHunterModels.ScanRequest;
import graphqlhunter.GraphQLHunterModels.ScanSettings;
import graphqlhunter.GraphQLHunterModels.ScanExecutionResult;
import graphqlhunter.auth.config.AuthConfigurationLoader;
import graphqlhunter.discovery.AutoDiscover;
import graphqlhunter.discovery.DiscoveryResult;
import graphqlhunter.importer.ImportedRequest;
import graphqlhunter.importer.RequestImporter;
import graphqlhunter.reporting.ReportingService;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTabbedPane;
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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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

        void runScan(ScanRequest request, ScanSettings settings, Consumer<ScanExecutionResult> onSuccess, Consumer<Throwable> onError);

        void validateAuth(ScanRequest request, AuthSettings settings, Consumer<String> onSuccess, Consumer<Throwable> onError);

        void publishIssues(ScanRequest request, List<Finding> findings, Consumer<Integer> onSuccess, Consumer<Throwable> onError);
    }

    private final GraphQLHunterActions actions;
    private final GraphQLHunterLogger logger;
    private final JTextField sourceField = new JTextField();
    private final JTextField urlField = new JTextField();
    private final JTextField methodField = new JTextField();
    private final JTextField delayField = new JTextField();
    private final JComboBox<ScanProfile> profileCombo = new JComboBox<>(ScanProfile.values());
    private final JCheckBox safeModeCheck = new JCheckBox("Safe mode");
    private final JComboBox<String> authModeCombo = new JComboBox<>(new String[]{"none", "imported_headers", "static_headers", "profile"});
    private final JComboBox<String> authProfileCombo = new JComboBox<>();
    private final JCheckBox authDetectFailuresCheck = new JCheckBox("Detect auth failures / retry once");
    private final JTextField importNameField = new JTextField("request.txt");
    private final JComboBox<String> importFormatCombo = new JComboBox<>(new String[]{"auto", "curl", "raw_http", "json", "yaml", "postman"});
    private final JComboBox<String> importedRequestCombo = new JComboBox<>();
    private final JTextArea queryArea = new JTextArea();
    private final JTextArea variablesArea = new JTextArea();
    private final JTextArea headersArea = new JTextArea();
    private final JTextArea authVarsArea = new JTextArea();
    private final JTextArea runtimeSecretsArea = new JTextArea();
    private final JTextArea authStaticHeadersArea = new JTextArea();
    private final JTextArea authImportedHeadersArea = new JTextArea();
    private final JTextArea authValidationArea = new JTextArea();
    private final JTextArea importContentArea = new JTextArea();
    private final JTextArea discoveryNotesArea = new JTextArea();
    private final JTextArea discoveryResultArea = new JTextArea();
    private final JTextArea detailsArea = new JTextArea();
    private final JTextArea logArea = new JTextArea();
    private final JLabel statusLabel = new JLabel("Ready.");
    private final JButton scanButton = new JButton("Run Focused GraphQL Checks");
    private final JButton validateAuthButton = new JButton("Validate Auth");
    private final JButton saveButton = new JButton("Save Request");
    private final JButton clearButton = new JButton("Clear Findings");
    private final JButton importParseButton = new JButton("Parse Import Content");
    private final JButton importApplyButton = new JButton("Apply Imported Request");
    private final JButton discoveryAnalyzeButton = new JButton("Analyze Notes");
    private final JButton discoveryApplyButton = new JButton("Apply Discovery");
    private final JButton exportJsonButton = new JButton("Export JSON");
    private final JButton exportHtmlButton = new JButton("Export HTML");
    private final JButton publishIssuesButton = new JButton("Publish to Burp");
    private final FindingTableModel findingTableModel = new FindingTableModel();
    private final JTable findingsTable = new JTable(findingTableModel);
    private final List<ImportedRequest> importedRequests = new ArrayList<>();
    private final ReportingService reportingService = new ReportingService();
    private DiscoveryResult latestDiscovery;
    private ScanExecutionResult lastScanResult;

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
        authImportedHeadersArea.setEditable(false);
        detailsArea.setLineWrap(true);
        detailsArea.setWrapStyleWord(true);
        logArea.setEditable(false);
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);
        authVarsArea.setLineWrap(true);
        authVarsArea.setWrapStyleWord(true);
        runtimeSecretsArea.setLineWrap(true);
        runtimeSecretsArea.setWrapStyleWord(true);
        authStaticHeadersArea.setLineWrap(true);
        authStaticHeadersArea.setWrapStyleWord(true);
        authImportedHeadersArea.setLineWrap(true);
        authImportedHeadersArea.setWrapStyleWord(true);
        authValidationArea.setLineWrap(true);
        authValidationArea.setWrapStyleWord(true);
        authValidationArea.setEditable(false);
        importContentArea.setLineWrap(true);
        importContentArea.setWrapStyleWord(true);
        discoveryNotesArea.setLineWrap(true);
        discoveryNotesArea.setWrapStyleWord(true);
        discoveryResultArea.setLineWrap(true);
        discoveryResultArea.setWrapStyleWord(true);
        discoveryResultArea.setEditable(false);

        AuthConfigurationLoader.configuration().profiles.keySet().forEach(authProfileCombo::addItem);

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
        validateAuthButton.addActionListener(event -> runAuthValidation());
        saveButton.addActionListener(event -> saveState());
        importParseButton.addActionListener(event -> parseImportedContent());
        importApplyButton.addActionListener(event -> applyImportedRequest());
        discoveryAnalyzeButton.addActionListener(event -> analyzeDiscovery());
        discoveryApplyButton.addActionListener(event -> applyDiscovery());
        exportJsonButton.addActionListener(event -> exportReport(false));
        exportHtmlButton.addActionListener(event -> exportReport(true));
        publishIssuesButton.addActionListener(event -> publishIssues());
        clearButton.addActionListener(event ->
        {
            findingTableModel.setRows(List.of());
            detailsArea.setText("");
            lastScanResult = null;
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
        applyImportedAuthHeaders(request.headers);
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
        buttonRow.add(publishIssuesButton);
        buttonRow.add(exportJsonButton);
        buttonRow.add(exportHtmlButton);
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

    private JTabbedPane buildEditorPanel()
    {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Request", buildRequestEditorPanel());
        tabs.addTab("Auth", buildAuthPanel());
        tabs.addTab("Import & Discovery", buildImportDiscoveryPanel());
        return tabs;
    }

    private JPanel buildRequestEditorPanel()
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

    private JPanel buildAuthPanel()
    {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("Mode"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 0.4;
        panel.add(authModeCombo, gbc);

        gbc.gridx = 2;
        gbc.weightx = 0;
        panel.add(new JLabel("Profile"), gbc);
        gbc.gridx = 3;
        gbc.weightx = 0.6;
        panel.add(authProfileCombo, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        panel.add(authDetectFailuresCheck, gbc);

        gbc.gridx = 2;
        gbc.gridwidth = 2;
        panel.add(validateAuthButton, gbc);

        gbc.gridy = 2;
        gbc.gridx = 0;
        gbc.weightx = 1.0;
        gbc.gridwidth = 4;
        gbc.weighty = 0.2;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(labeledScroll("Auth Variables (key=value)", authVarsArea, 160), gbc);

        gbc.gridy = 3;
        panel.add(labeledScroll("Runtime-only Secrets (not persisted)", runtimeSecretsArea, 120), gbc);

        gbc.gridy = 4;
        panel.add(labeledScroll("Static Auth Headers", authStaticHeadersArea, 140), gbc);

        gbc.gridy = 5;
        panel.add(labeledScroll("Imported Auth Headers (read-only)", authImportedHeadersArea, 140), gbc);

        gbc.gridy = 6;
        panel.add(labeledScroll("Auth Validation Result", authValidationArea, 160), gbc);

        return panel;
    }

    private JPanel buildImportDiscoveryPanel()
    {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0;
        gbc.gridy = 0;
        panel.add(new JLabel("Import name"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 0.5;
        panel.add(importNameField, gbc);
        gbc.gridx = 2;
        gbc.weightx = 0;
        panel.add(new JLabel("Format"), gbc);
        gbc.gridx = 3;
        gbc.weightx = 0.3;
        panel.add(importFormatCombo, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 4;
        gbc.weightx = 1.0;
        gbc.weighty = 0.32;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(labeledScroll("Import Content", importContentArea, 180), gbc);

        JPanel importButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        importButtons.add(importParseButton);
        importButtons.add(importedRequestCombo);
        importButtons.add(importApplyButton);

        gbc.gridy = 2;
        gbc.weighty = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(importButtons, gbc);

        gbc.gridy = 3;
        gbc.weighty = 0.25;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(labeledScroll("Discovery Notes / Artifacts", discoveryNotesArea, 160), gbc);

        JPanel discoveryButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        discoveryButtons.add(discoveryAnalyzeButton);
        discoveryButtons.add(discoveryApplyButton);

        gbc.gridy = 4;
        gbc.weighty = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(discoveryButtons, gbc);

        gbc.gridy = 5;
        gbc.weighty = 0.25;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(labeledScroll("Discovery Result", discoveryResultArea, 180), gbc);

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
        if (state.authSettings != null)
        {
            authModeCombo.setSelectedItem(state.authSettings.mode == null || state.authSettings.mode.isBlank() ? "none" : state.authSettings.mode);
            if (state.authSettings.profileName != null && !state.authSettings.profileName.isBlank())
            {
                authProfileCombo.setSelectedItem(state.authSettings.profileName);
            }
            authDetectFailuresCheck.setSelected(state.authSettings.detectFailures);
            authVarsArea.setText(renderKeyValueMap(state.authSettings.authVars));
            runtimeSecretsArea.setText(renderKeyValueMap(state.authSettings.runtimeOnlySecrets));
            authStaticHeadersArea.setText(renderHeaders(state.authSettings.staticHeaders));
            authImportedHeadersArea.setText(renderHeaders(state.authSettings.importedAuthHeaders));
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
        state.authSettings = buildAuthSettingsFromInputs(current == null ? null : current.authSettings);
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
        lastScanResult = null;

        actions.runScan(request, settings, result ->
        {
            lastScanResult = result;
            findingTableModel.setRows(result.findings);
            statusLabel.setText(buildScanStatusMessage(result));
            scanButton.setEnabled(true);
            if (!result.findings.isEmpty())
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

    private void runAuthValidation()
    {
        ScanRequest request = buildRequestFromInputs();
        AuthSettings settings = buildAuthSettingsFromInputs(actions.currentState() == null ? null : actions.currentState().authSettings);
        if (request.url == null || request.url.isBlank())
        {
            statusLabel.setText("URL is required for auth validation.");
            return;
        }
        validateAuthButton.setEnabled(false);
        authValidationArea.setText("Running auth validation...");
        actions.validateAuth(request, settings, result ->
        {
            authValidationArea.setText(result);
            validateAuthButton.setEnabled(true);
        }, throwable ->
        {
            authValidationArea.setText("Validation failed: " + throwable.getMessage());
            validateAuthButton.setEnabled(true);
        });
    }

    private void parseImportedContent()
    {
        try
        {
            importedRequests.clear();
            String format = String.valueOf(importFormatCombo.getSelectedItem());
            List<ImportedRequest> parsed = switch (format)
            {
                case "curl" -> List.of(RequestImporter.fromCurlCommand(importContentArea.getText()));
                case "raw_http" -> List.of(RequestImporter.fromRawHttp(importContentArea.getText()));
                case "json" -> List.of(RequestImporter.fromJsonContent(importContentArea.getText()));
                case "yaml" -> List.of(RequestImporter.fromYamlContent(importContentArea.getText()));
                case "postman" -> RequestImporter.fromPostmanCollectionContent(importContentArea.getText());
                default -> RequestImporter.autoDetect(importNameField.getText(), importContentArea.getText());
            };
            importedRequests.addAll(parsed);
            importedRequestCombo.removeAllItems();
            importedRequests.forEach(request ->
                importedRequestCombo.addItem((request.folder == null || request.folder.isBlank() ? "" : request.folder + " / ") + request.name)
            );
            statusLabel.setText("Parsed " + importedRequests.size() + " imported request(s).");
        }
        catch (Exception exception)
        {
            statusLabel.setText("Import parse failed: " + exception.getMessage());
            logger.warn("Import parse failed: " + exception.getMessage());
        }
    }

    private void applyImportedRequest()
    {
        int selectedIndex = importedRequestCombo.getSelectedIndex();
        if (selectedIndex < 0 || selectedIndex >= importedRequests.size())
        {
            statusLabel.setText("No imported request selected.");
            return;
        }
        importRequest(importedRequests.get(selectedIndex).toScanRequest());
        statusLabel.setText("Applied imported request to current scan target.");
    }

    private void analyzeDiscovery()
    {
        try
        {
            AutoDiscover discoverer = new AutoDiscover();
            latestDiscovery = discoverer.autoDiscover(importNameField.getText(), discoveryNotesArea.getText());
            StringBuilder builder = new StringBuilder();
            builder.append("URL: ").append(String.valueOf(latestDiscovery.url)).append(System.lineSeparator());
            builder.append("Auth method: ").append(String.valueOf(latestDiscovery.authMethod)).append(System.lineSeparator()).append(System.lineSeparator());
            if (!latestDiscovery.headers.isEmpty())
            {
                builder.append("Headers").append(System.lineSeparator());
                latestDiscovery.headers.forEach((key, value) -> builder.append(key).append(": ").append(value).append(System.lineSeparator()));
                builder.append(System.lineSeparator());
            }
            if (!latestDiscovery.credentials.isEmpty())
            {
                builder.append("Credentials").append(System.lineSeparator());
                latestDiscovery.credentials.forEach((key, value) -> builder.append(key).append("=").append(value).append(System.lineSeparator()));
                builder.append(System.lineSeparator());
            }
            builder.append("Recommendations").append(System.lineSeparator()).append(GraphQLHunterJson.write(latestDiscovery.recommendations));
            discoveryResultArea.setText(builder.toString());
            statusLabel.setText("Discovery analysis complete.");
        }
        catch (Exception exception)
        {
            discoveryResultArea.setText("Discovery failed: " + exception.getMessage());
            statusLabel.setText("Discovery failed.");
        }
    }

    private void applyDiscovery()
    {
        if (latestDiscovery == null)
        {
            statusLabel.setText("No discovery result to apply.");
            return;
        }
        if (latestDiscovery.url != null && !latestDiscovery.url.isBlank())
        {
            urlField.setText(latestDiscovery.url);
        }
        if ("token_auth".equals(String.valueOf(latestDiscovery.recommendations.get("auth_profile"))))
        {
            authModeCombo.setSelectedItem("profile");
            authProfileCombo.setSelectedItem("token_auth");
            @SuppressWarnings("unchecked")
            List<String> authVars = (List<String>) latestDiscovery.recommendations.getOrDefault("auth_vars", List.of());
            LinkedHashMap<String, String> values = parseKeyValueLines(authVars);
            authVarsArea.setText(renderKeyValueMap(values));
        }
        else if (!recommendationHeaders(latestDiscovery).isEmpty())
        {
            authModeCombo.setSelectedItem("static_headers");
            authStaticHeadersArea.setText(renderHeaders(recommendationHeaders(latestDiscovery)));
        }
        statusLabel.setText("Applied discovery result to current configuration.");
    }

    private void exportReport(boolean html)
    {
        List<Finding> findings = findingTableModel.all();
        if (findings.isEmpty())
        {
            statusLabel.setText("No findings available to export.");
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File(html ? "graphql-hunter-report.html" : "graphql-hunter-report.json"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION)
        {
            return;
        }
        Path path = chooser.getSelectedFile().toPath();
        try
        {
            ScanExecutionResult result = currentExportResult(findings);
            String content = html
                ? reportingService.toHtmlReport(result)
                : reportingService.toJsonReport(result);
            Files.writeString(path, content);
            statusLabel.setText("Exported report to " + path.getFileName());
        }
        catch (IOException exception)
        {
            statusLabel.setText("Failed to export report: " + exception.getMessage());
        }
    }

    private void publishIssues()
    {
        List<Finding> findings = findingTableModel.all();
        if (findings.isEmpty())
        {
            statusLabel.setText("No findings available to publish.");
            return;
        }
        publishIssuesButton.setEnabled(false);
        statusLabel.setText("Publishing findings to Burp...");
        ScanExecutionResult result = currentExportResult(findings);
        actions.publishIssues(result.request, result.findings, published ->
        {
            statusLabel.setText("Published " + published + " finding(s) to Burp.");
            publishIssuesButton.setEnabled(true);
        }, throwable ->
        {
            statusLabel.setText("Issue publication failed: " + throwable.getMessage());
            publishIssuesButton.setEnabled(true);
        });
    }

    private ScanExecutionResult currentExportResult(List<Finding> findings)
    {
        if (lastScanResult != null && lastScanResult.findings != null && !lastScanResult.findings.isEmpty())
        {
            return lastScanResult;
        }
        ScanExecutionResult fallback = new ScanExecutionResult();
        fallback.request = buildRequestFromInputs();
        fallback.settings = buildScanSettingsFromInputs();
        fallback.findings = new ArrayList<>(findings);
        fallback.status = "completed";
        return fallback;
    }

    private String buildScanStatusMessage(ScanExecutionResult result)
    {
        int findingCount = result.findings == null ? 0 : result.findings.size();
        int failureCount = result.failedScanners == null ? 0 : result.failedScanners.size();
        if (failureCount > 0)
        {
            return "Partial scan: " + findingCount + " finding(s), " + failureCount + " scanner failure(s).";
        }
        return "Completed " + findingCount + " finding(s).";
    }

    private AuthSettings buildAuthSettingsFromInputs(AuthSettings existing)
    {
        AuthSettings settings = existing == null ? new AuthSettings() : existing.copy();
        settings.mode = String.valueOf(authModeCombo.getSelectedItem());
        settings.profileName = authProfileCombo.getSelectedItem() == null ? "" : String.valueOf(authProfileCombo.getSelectedItem());
        settings.detectFailures = authDetectFailuresCheck.isSelected();
        settings.authVars = parseKeyValueMap(authVarsArea.getText());
        settings.runtimeOnlySecrets = parseKeyValueMap(runtimeSecretsArea.getText());
        settings.staticHeaders = parseHeaders(authStaticHeadersArea.getText());
        settings.importedAuthHeaders = parseHeaders(authImportedHeadersArea.getText());
        return settings;
    }

    private void applyImportedAuthHeaders(Map<String, String> headers)
    {
        Map<String, String> importedAuthHeaders = extractImportedAuthHeaders(headers);
        if (importedAuthHeaders.isEmpty())
        {
            return;
        }
        authImportedHeadersArea.setText(renderHeaders(importedAuthHeaders));
        if ("none".equals(String.valueOf(authModeCombo.getSelectedItem())))
        {
            authModeCombo.setSelectedItem("imported_headers");
        }
    }

    private Map<String, String> extractImportedAuthHeaders(Map<String, String> headers)
    {
        LinkedHashMap<String, String> authHeaders = new LinkedHashMap<>();
        if (headers == null)
        {
            return authHeaders;
        }
        headers.forEach((key, value) ->
        {
            if (key == null)
            {
                return;
            }
            String lowered = key.toLowerCase(Locale.ROOT);
            if (lowered.equals("authorization")
                || lowered.equals("cookie")
                || lowered.equals("token")
                || lowered.equals("x-api-key")
                || lowered.equals("x-auth-token"))
            {
                authHeaders.put(key, value);
            }
        });
        return authHeaders;
    }

    private Map<String, String> recommendationHeaders(DiscoveryResult result)
    {
        LinkedHashMap<String, String> headers = new LinkedHashMap<>();
        Object recommended = result.recommendations.get("headers");
        if (recommended instanceof List<?> list)
        {
            list.stream()
                .map(String::valueOf)
                .filter(line -> line.contains(":"))
                .forEach(line ->
                {
                    String[] parts = line.split(":", 2);
                    headers.put(parts[0].trim(), parts[1].trim());
                });
        }
        if (headers.isEmpty())
        {
            headers.putAll(result.headers);
        }
        return headers;
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

    private Map<String, String> parseKeyValueMap(String text)
    {
        LinkedHashMap<String, String> values = new LinkedHashMap<>();
        if (text == null || text.isBlank())
        {
            return values;
        }
        for (String line : text.split("\\R"))
        {
            if (line == null || line.isBlank() || !line.contains("="))
            {
                continue;
            }
            String[] parts = line.split("=", 2);
            values.put(parts[0].trim(), parts[1].trim());
        }
        return values;
    }

    private LinkedHashMap<String, String> parseKeyValueLines(List<String> lines)
    {
        LinkedHashMap<String, String> values = new LinkedHashMap<>();
        for (String line : lines)
        {
            if (line == null || !line.contains("="))
            {
                continue;
            }
            String[] parts = line.split("=", 2);
            values.put(parts[0].trim(), parts[1].trim());
        }
        return values;
    }

    private String renderHeaders(Map<String, String> headers)
    {
        StringBuilder builder = new StringBuilder();
        headers.forEach((key, value) -> builder.append(key).append(": ").append(value).append(System.lineSeparator()));
        return builder.toString().trim();
    }

    private String renderKeyValueMap(Map<String, String> values)
    {
        StringBuilder builder = new StringBuilder();
        values.forEach((key, value) -> builder.append(key).append('=').append(value).append(System.lineSeparator()));
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

        public List<Finding> all()
        {
            return new ArrayList<>(rows);
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
