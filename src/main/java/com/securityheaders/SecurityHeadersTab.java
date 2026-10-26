package com.securityheaders;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import com.securityheaders.testcase.*;

public class SecurityHeadersTab extends JPanel {

    private static final Color BG = new Color(22, 24, 30);
    private static final Color BG2 = new Color(28, 31, 38);
    private static final Color BG_ELEV = new Color(34, 37, 45);
    private static final Color BG_INPUT = new Color(26, 28, 35);
    private static final Color BORDER = new Color(44, 48, 58);
    private static final Color BORDER_S = new Color(38, 42, 50);
    private static final Color TXT = new Color(200, 204, 212);
    private static final Color TXT2 = new Color(130, 136, 152);
    private static final Color TXT_M = new Color(85, 92, 108);
    private static final Color ACCENT = new Color(88, 146, 240);
    private static final Color ACCENT_H = new Color(110, 164, 252);
    private static final Color ACCENT_DIM = new Color(55, 90, 150);
    private static final Color HI = new Color(0xFF, 0xFF, 0xFF);
    private static final Color GREEN_BG = new Color(20, 42, 30);
    private static final Color GREEN_FG = new Color(76, 175, 110);
    private static final Color RED_BG = new Color(45, 22, 26);
    private static final Color RED_FG = new Color(210, 95, 100);
    private static final Color WARN_BG = new Color(42, 38, 22);
    private static final Color WARN_FG = new Color(195, 165, 80);
    private static final Color ORANGE_BG = new Color(45, 35, 20);
    private static final Color ORANGE_FG = new Color(230, 150, 50);
    private static final Color TBL_HDR = new Color(28, 31, 38);
    private static final Color TBL_EVEN = new Color(24, 26, 32);
    private static final Color TBL_ODD = new Color(28, 31, 38);
    private static final Color TBL_SEL = new Color(36, 52, 82);
    private static final Color TBL_DIV = new Color(36, 40, 48);
    private static final Color BTN_MUTED = new Color(52, 56, 68);
    private static final Color BTN_MUTED_H = new Color(62, 66, 78);

    private final ResultStore resultStore;
    private final ResultStore repeaterResultStore;
    private final ScopeManager scopeManager;
    private final HeaderCheckHttpHandler handler;
    private final TestcaseLibrary library;
    private final TestcaseResultStore tcResultStore;
    private final EndpointRegistry endpointRegistry;
    private final ApprovedBaseline baseline;
    private final ActiveRunner activeRunner;
    private final TestcaseSelector selector;
    private final ScanHealthTracker healthTracker;
    private final ResultFilterService filterService = new ResultFilterService();
    private final SummaryService summaryService = new SummaryService();
    private final CsvExportService csvExport = new CsvExportService();

    private JTabbedPane mainTabs;

    // Dashboard KPI labels
    private JLabel dashHosts, dashEndpoints, dashAssessed, dashTestcases, dashMissing, dashErrors;

    // Dashboard header coverage
    private static final String[] COV_LABELS = {"HSTS", "Cache-Control", "X-Frame-Options", "X-Content-Type-Options", "ACAO", "CSP"};
    private final JPanel[] dashCovBars = new JPanel[6];
    private final JLabel[] dashCovPcts = new JLabel[6];
    private final JLabel[] dashCovStats = new JLabel[6];
    private final int[] dashCovPresent = new int[6];
    private final int[] dashCovTotal = new int[6];

    // Dashboard security posture
    private JLabel dashAffected, dashCompliant, dashCompliance, dashNoHeaders;

    // Dashboard scan health labels
    private JLabel dashProcessed, dashChecksMin, dashHeap, dashElapsed, dashLastUpdate, dashTcErrors;

    private final ResultsTableModel rawTableModel = new ResultsTableModel();
    private final HostSummaryTableModel hostTableModel = new HostSummaryTableModel();
    private final EndpointSummaryTableModel epTableModel = new EndpointSummaryTableModel();
    private final ResultsTableModel repeaterTableModel = new ResultsTableModel();
    private TestcaseResultsTableModel tcTableModel;

    // Raw Results filter controls
    private JTextField rawSearchField;
    private JComboBox<String> rawHostCombo;
    private JComboBox<String> rawStatusCombo;
    private JComboBox<String> rawHeaderCombo;
    private JLabel rawFilterIndicator;

    // Repeater filter controls
    private JTextField repSearchField;
    private JComboBox<String> repHostCombo;
    private JComboBox<String> repStatusCombo;
    private JComboBox<String> repHeaderCombo;
    private JLabel repFilterIndicator;

    // Host Summary filter controls
    private JTextField hostSearchField;
    private JComboBox<String> hostHeaderCombo;
    private JLabel hostFilterIndicator;

    // Endpoint Summary filter controls
    private JTextField epSearchField;
    private JComboBox<String> epHostCombo;
    private JComboBox<String> epHeaderCombo;
    private JLabel epFilterIndicator;

    // Catalog filter
    private JTextField catalogSearchField;

    private JLabel statusLabel;
    private JLabel monitorLabel;

    // Summary card labels
    private JLabel cardResponses, cardWithMissing, cardHosts, cardMissingOccur;
    private JLabel cardTcTotal, cardTcPass, cardTcFail, cardTcError;

    // Testcase filter
    private JComboBox<String> tcModeCombo;
    private JComboBox<String> tcStatusCombo;
    private JComboBox<String> tcCategoryCombo;
    private JComboBox<String> tcHostCombo;
    private JTextField tcPathField;

    private List<HeaderResult> currentFiltered = new ArrayList<>();
    private List<HeaderResult> currentRepFiltered = new ArrayList<>();
    private List<TestcaseResult> currentTcFiltered = new ArrayList<>();
    private volatile boolean refreshingCombos = false;

    public SecurityHeadersTab(ResultStore resultStore, ResultStore repeaterResultStore,
                              ScopeManager scopeManager, HeaderCheckHttpHandler handler,
                              TestcaseLibrary library, TestcaseResultStore tcResultStore,
                              EndpointRegistry endpointRegistry, ApprovedBaseline baseline,
                              ActiveRunner activeRunner, TestcaseSelector selector,
                              ScanHealthTracker healthTracker) {
        this.resultStore = resultStore;
        this.repeaterResultStore = repeaterResultStore;
        this.scopeManager = scopeManager;
        this.handler = handler;
        this.library = library;
        this.tcResultStore = tcResultStore;
        this.endpointRegistry = endpointRegistry;
        this.baseline = baseline;
        this.activeRunner = activeRunner;
        this.selector = selector;
        this.healthTracker = healthTracker;
        this.tcTableModel = new TestcaseResultsTableModel(library);

        setLayout(new BorderLayout());
        setBackground(BG);

        add(createBanner(), BorderLayout.NORTH);

        JPanel mainBody = new JPanel(new BorderLayout());
        mainBody.setBackground(BG);

        monitorLabel = new JLabel("● Monitoring");
        monitorLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        monitorLabel.setForeground(GREEN_FG);
        monitorLabel.setOpaque(false);

        JTabbedPane tabs = createTabbedContent();
        JPanel tabOverlay = new JPanel(null) {
            @Override public void doLayout() {
                tabs.setBounds(0, 0, getWidth(), getHeight());
                Dimension pref = monitorLabel.getPreferredSize();
                java.awt.Rectangle tabBounds = tabs.getUI().getTabBounds(tabs, 0);
                int y = (tabBounds != null) ? (tabBounds.height - pref.height) / 2 : 4;
                monitorLabel.setBounds(getWidth() - pref.width - 14, y, pref.width, pref.height);
            }
            @Override public Dimension getPreferredSize() { return tabs.getPreferredSize(); }
            @Override public Dimension getMinimumSize() { return tabs.getMinimumSize(); }
        };
        tabOverlay.setBackground(BG);
        tabOverlay.add(monitorLabel);
        tabOverlay.add(tabs);
        mainBody.add(tabOverlay, BorderLayout.CENTER);

        add(mainBody, BorderLayout.CENTER);
        add(createStatusBar(), BorderLayout.SOUTH);

        refreshViews();

        javax.swing.Timer dashTimer = new javax.swing.Timer(5000, e -> {
            refreshDashboard();
            applyEpFilters();
        });
        dashTimer.setRepeats(true);
        dashTimer.start();
    }

    // ─── Banner ──────────────────────────────────────────────────────────────

    private JPanel createBanner() {
        JPanel banner = new JPanel(new BorderLayout()) {
            @Override protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                g.setColor(ACCENT);
                g.fillRect(0, 0, getWidth(), 2);
            }
        };
        banner.setBackground(BG2);
        banner.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER),
                new EmptyBorder(14, 20, 12, 20)));

        JLabel title = new JLabel("Security Headers Analyzer");
        title.setIcon(createIcon(22, ACCENT, "shield"));
        title.setIconTextGap(10);
        title.setFont(new Font("SansSerif", Font.BOLD, 18));
        title.setForeground(TXT);
        JLabel sub = new JLabel("Detect. Analyze. Secure.");
        sub.setFont(new Font("SansSerif", Font.PLAIN, 12));
        sub.setForeground(TXT_M);

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        left.setOpaque(false);
        JPanel tt = new JPanel();
        tt.setOpaque(false);
        tt.setLayout(new BoxLayout(tt, BoxLayout.Y_AXIS));
        tt.add(title); tt.add(Box.createVerticalStrut(2)); tt.add(sub);
        left.add(tt);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        right.setOpaque(false);

        Color ON_BG = ACCENT;
        Color OFF_BG = new Color(42, 36, 40);

        JButton enableBtn = pill("Enabled", ACCENT, ACCENT_H);
        enableBtn.setFont(new Font("SansSerif", Font.BOLD, 14));
        enableBtn.addActionListener(e -> {
            boolean on = !handler.isEnabled();
            handler.setEnabled(on);
            enableBtn.setText(on ? "Enabled" : "Disabled");
            enableBtn.putClientProperty("pill.restBg", on ? ON_BG : OFF_BG);
            enableBtn.putClientProperty("pill.hoverBg", on ? ACCENT : OFF_BG);
            enableBtn.setBackground(on ? ON_BG : OFF_BG);
            enableBtn.setForeground(on ? HI : TXT_M);
            statusLabel.setText(on ? "Monitoring" : "Paused");
            statusLabel.setForeground(on ? ACCENT : TXT_M);
            monitorLabel.setText(on ? "● Monitoring" : "■ Stopped");
            monitorLabel.setForeground(on ? GREEN_FG : RED_FG);
        });

        JButton passiveBtn = pill("Passive Scan", ACCENT_DIM, ACCENT);
        passiveBtn.setFont(new Font("SansSerif", Font.BOLD, 14));
        passiveBtn.setToolTipText("Toggle Passive Scanning");
        passiveBtn.addActionListener(e -> {
            boolean on = !handler.isPassiveEnabled();
            handler.setPassiveEnabled(on);
            passiveBtn.putClientProperty("pill.restBg", on ? ON_BG : OFF_BG);
            passiveBtn.putClientProperty("pill.hoverBg", on ? ACCENT : OFF_BG);
            passiveBtn.setBackground(on ? ON_BG : OFF_BG);
            passiveBtn.setForeground(on ? HI : TXT_M);
            passiveBtn.setToolTipText(on ? "Passive ON" : "Passive OFF");
        });

        JButton activeBtn = pill("Active Scan", ACCENT_DIM, ACCENT);
        activeBtn.setFont(new Font("SansSerif", Font.BOLD, 14));
        activeBtn.setToolTipText("Toggle Active Scanning");
        activeBtn.addActionListener(e -> {
            boolean on = !handler.isActiveEnabled();
            handler.setActiveEnabled(on);
            activeBtn.putClientProperty("pill.restBg", on ? ON_BG : OFF_BG);
            activeBtn.putClientProperty("pill.hoverBg", on ? ACCENT : OFF_BG);
            activeBtn.setBackground(on ? ON_BG : OFF_BG);
            activeBtn.setForeground(on ? HI : TXT_M);
            activeBtn.setToolTipText(on ? "Active ON" : "Active OFF");
        });

        JButton clearBtn = pill("Clear", RED_FG, new Color(230, 110, 115));
        clearBtn.setFont(new Font("SansSerif", Font.BOLD, 14));
        clearBtn.setForeground(HI);
        clearBtn.addActionListener(e -> {
            int choice = JOptionPane.showConfirmDialog(SecurityHeadersTab.this,
                    "Are you sure you want to clear all data?",
                    "Clear Data", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) return;
            resultStore.clear();
            repeaterResultStore.clear();
            tcResultStore.clear();
            endpointRegistry.clear();
            handler.clearSeenUrls();
            if (healthTracker != null) healthTracker.reset();
            refreshViews();
            refreshRepeaterViews();
            refreshTestcaseViews();
            statusLabel.setText("Cleared");
            statusLabel.setForeground(TXT_M);
        });
        right.add(passiveBtn);
        right.add(activeBtn);
        right.add(enableBtn);
        right.add(clearBtn);

        banner.add(left, BorderLayout.WEST);
        banner.add(right, BorderLayout.EAST);
        return banner;
    }

    // ─── Summary Cards ───────────────────────────────────────────────────────

    private JPanel createSummaryCards() {
        JPanel wrapper = new JPanel();
        wrapper.setOpaque(false);
        wrapper.setLayout(new BoxLayout(wrapper, BoxLayout.Y_AXIS));

        JPanel row1 = new JPanel(new GridLayout(1, 4, 8, 0));
        row1.setOpaque(false);
        row1.setBorder(new EmptyBorder(8, 14, 3, 14));

        cardResponses = new JLabel("0");
        cardWithMissing = new JLabel("0");
        cardHosts = new JLabel("0");
        cardMissingOccur = new JLabel("0");

        row1.add(summaryCard("Responses", cardResponses, ACCENT));
        row1.add(summaryCard("Missing Headers", cardWithMissing, RED_FG));
        row1.add(summaryCard("Hosts", cardHosts, ACCENT));
        row1.add(summaryCard("Missing Total", cardMissingOccur, RED_FG));

        JPanel row2 = new JPanel(new GridLayout(1, 4, 8, 0));
        row2.setOpaque(false);
        row2.setBorder(new EmptyBorder(3, 14, 3, 14));

        cardTcTotal = new JLabel("0");
        cardTcPass = new JLabel("0");
        cardTcFail = new JLabel("0");
        cardTcError = new JLabel("0");

        row2.add(summaryCard("Testcases", cardTcTotal, ACCENT));
        row2.add(summaryCard("Passed", cardTcPass, GREEN_FG));
        row2.add(summaryCard("Failed", cardTcFail, RED_FG));
        row2.add(summaryCard("Errors", cardTcError, WARN_FG));

        wrapper.add(row1);
        wrapper.add(row2);
        return wrapper;
    }

    private JPanel summaryCard(String label, JLabel valueLabel, Color accent) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBackground(BG_ELEV);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_S),
                new EmptyBorder(7, 12, 7, 12)));
        JLabel lbl = new JLabel(label.toUpperCase());
        lbl.setFont(new Font("SansSerif", Font.PLAIN, 11));
        lbl.setForeground(TXT_M);
        valueLabel.setFont(new Font("SansSerif", Font.BOLD, 20));
        valueLabel.setForeground(accent);
        card.add(lbl, BorderLayout.NORTH);
        card.add(valueLabel, BorderLayout.CENTER);
        return card;
    }

    // ─── Tabbed Content ──────────────────────────────────────────────────────

    private JTabbedPane createTabbedContent() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.setBackground(BG);
        tabs.setForeground(TXT);
        tabs.setFont(new Font("SansSerif", Font.PLAIN, 13));

        tabs.addTab("Dashboard", createIcon(14, ACCENT, "dash"), createDashboardPanel(), null);
        tabs.addTab("Raw Results", createIcon(14, ACCENT, "grid"), createRawResultsPanel(), null);
        tabs.addTab("Host Summary", createIcon(14, ACCENT, "globe"), createHostSummaryPanel(), null);
        tabs.addTab("Endpoint Summary", createIcon(14, ACCENT, "endpoint"), createEndpointSummaryPanel(), null);
        tabs.addTab("Repeater Requests", createIcon(14, ACCENT, "repeat"), createRepeaterPanel(), null);
        tabs.addTab("Testcase Catalog", createIcon(14, TXT2, "list"), createCatalogPanel(), null);
        tabs.addTab("Testcase Results", createIcon(14, GREEN_FG, "check"), createTestcasePanel(), null);
        tabs.addTab("Scope & Export", createIcon(14, TXT2, "gear"), createScopeExportPanel(), null);

        mainTabs = tabs;
        return tabs;
    }

    // ─── Dashboard Panel ──────────────────────────────────────────────────────

    private JPanel createDashboardPanel() {
        JPanel dash = new JPanel();
        dash.setLayout(new BoxLayout(dash, BoxLayout.Y_AXIS));
        dash.setBackground(BG);
        dash.setBorder(new EmptyBorder(10, 14, 10, 14));

        // ── KPI Cards ──
        dash.add(dashSectionLabel("SCAN OVERVIEW"));
        dash.add(Box.createVerticalStrut(6));

        JPanel kpiRow = new JPanel(new GridLayout(1, 6, 8, 0));
        kpiRow.setOpaque(false);
        kpiRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        kpiRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 70));

        dashHosts = new JLabel("0");
        dashEndpoints = new JLabel("0");
        dashAssessed = new JLabel("0");
        dashTestcases = new JLabel("0");
        dashMissing = new JLabel("0");
        dashErrors = new JLabel("0");

        kpiRow.add(summaryCard("Unique Hosts", dashHosts, ACCENT));
        kpiRow.add(summaryCard("Endpoints", dashEndpoints, ACCENT));
        kpiRow.add(summaryCard("Assessed", dashAssessed, ACCENT));
        kpiRow.add(summaryCard("Testcases", dashTestcases, GREEN_FG));
        kpiRow.add(summaryCard("Missing", dashMissing, RED_FG));
        kpiRow.add(summaryCard("Errors", dashErrors, RED_FG));

        dash.add(kpiRow);
        dash.add(Box.createVerticalStrut(24));

        // ── Header Coverage ──
        dash.add(dashSectionLabel("HEADER COVERAGE"));
        dash.add(Box.createVerticalStrut(6));

        JPanel covPanel = new JPanel();
        covPanel.setLayout(new BoxLayout(covPanel, BoxLayout.Y_AXIS));
        covPanel.setOpaque(false);
        covPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        for (int i = 0; i < 6; i++) {
            dashCovPcts[i] = new JLabel("—");
            dashCovStats[i] = new JLabel("0 / 0");
            covPanel.add(createCoverageRow(COV_LABELS[i], i));
            if (i < 5) covPanel.add(Box.createVerticalStrut(3));
        }
        covPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, covPanel.getPreferredSize().height + 20));
        dash.add(covPanel);
        dash.add(Box.createVerticalStrut(24));

        // ── Security Posture ──
        dash.add(dashSectionLabel("SECURITY POSTURE"));
        dash.add(Box.createVerticalStrut(6));

        JPanel postureRow = new JPanel(new GridLayout(1, 4, 8, 0));
        postureRow.setOpaque(false);
        postureRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        postureRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 70));

        dashAffected = new JLabel("0");
        dashCompliant = new JLabel("0");
        dashCompliance = new JLabel("—");
        dashNoHeaders = new JLabel("0");

        JPanel affectedCard = summaryCard("Affected Endpoints", dashAffected, RED_FG);
        affectedCard.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        affectedCard.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (mainTabs != null) {
                    mainTabs.setSelectedIndex(3);
                    epHeaderCombo.setSelectedIndex(1);
                }
            }
        });

        JPanel compliantCard = summaryCard("Fully Compliant", dashCompliant, GREEN_FG);
        compliantCard.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        compliantCard.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (mainTabs != null) {
                    mainTabs.setSelectedIndex(3);
                    epHeaderCombo.setSelectedIndex(0);
                }
            }
        });

        JPanel complianceCard = summaryCard("Header Compliance", dashCompliance, ACCENT);

        JPanel noHeadersCard = summaryCard("No Security Headers", dashNoHeaders, ORANGE_FG);
        noHeadersCard.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        noHeadersCard.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (mainTabs != null) {
                    mainTabs.setSelectedIndex(1);
                    rawHeaderCombo.setSelectedIndex(2);
                }
            }
        });

        postureRow.add(affectedCard);
        postureRow.add(compliantCard);
        postureRow.add(complianceCard);
        postureRow.add(noHeadersCard);
        dash.add(postureRow);
        dash.add(Box.createVerticalStrut(24));

        // ── Scan Health ──
        dash.add(dashSectionLabel("SCAN HEALTH"));
        dash.add(Box.createVerticalStrut(6));

        JPanel healthRow = new JPanel(new GridLayout(1, 6, 8, 0));
        healthRow.setOpaque(false);
        healthRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        healthRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 70));

        dashProcessed = new JLabel("0");
        dashChecksMin = new JLabel("—");
        dashHeap = new JLabel("—");
        dashElapsed = new JLabel("—");
        dashLastUpdate = new JLabel("—");
        dashTcErrors = new JLabel("0");

        healthRow.add(summaryCard("Processed", dashProcessed, ACCENT));
        healthRow.add(summaryCard("Checks/min", dashChecksMin, ACCENT));
        healthRow.add(summaryCard("Heap Used", dashHeap, WARN_FG));
        healthRow.add(summaryCard("Elapsed", dashElapsed, TXT2));
        healthRow.add(summaryCard("Last Activity", dashLastUpdate, TXT2));
        healthRow.add(summaryCard("TC Errors", dashTcErrors, RED_FG));

        dash.add(healthRow);

        dash.add(Box.createVerticalGlue());

        JScrollPane scrollPane = new JScrollPane(dash);
        scrollPane.setBorder(null);
        scrollPane.getViewport().setBackground(BG);
        scrollPane.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBackground(BG);
        wrapper.add(scrollPane, BorderLayout.CENTER);
        return wrapper;
    }

    private JPanel createCoverageRow(String headerName, int index) {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.setBackground(BG_ELEV);
        row.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_S),
                new EmptyBorder(5, 12, 5, 12)));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 32));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel name = new JLabel(headerName);
        name.setFont(new Font("SansSerif", Font.BOLD, 12));
        name.setForeground(TXT);
        name.setPreferredSize(new Dimension(180, 20));

        final int idx = index;
        JPanel barTrack = new JPanel() {
            @Override protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(BORDER);
                g2.fillRoundRect(0, 2, getWidth(), getHeight() - 4, 6, 6);
                int total = dashCovTotal[idx];
                int present = dashCovPresent[idx];
                if (total > 0 && present > 0) {
                    int pct = present * 100 / total;
                    int barWidth = Math.max(4, (int) ((double) present / total * getWidth()));
                    Color barColor = pct >= 80 ? GREEN_FG : pct >= 50 ? WARN_FG : RED_FG;
                    g2.setColor(barColor);
                    g2.fillRoundRect(0, 2, barWidth, getHeight() - 4, 6, 6);
                }
                g2.dispose();
            }
        };
        barTrack.setOpaque(false);
        barTrack.setPreferredSize(new Dimension(200, 18));
        dashCovBars[index] = barTrack;

        dashCovPcts[index].setFont(new Font("SansSerif", Font.BOLD, 12));
        dashCovPcts[index].setForeground(TXT);
        dashCovPcts[index].setHorizontalAlignment(SwingConstants.RIGHT);
        dashCovPcts[index].setPreferredSize(new Dimension(50, 20));

        dashCovStats[index].setFont(new Font("SansSerif", Font.PLAIN, 12));
        dashCovStats[index].setForeground(TXT2);
        dashCovStats[index].setHorizontalAlignment(SwingConstants.RIGHT);
        dashCovStats[index].setPreferredSize(new Dimension(90, 20));

        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        rightPanel.setOpaque(false);
        rightPanel.add(dashCovPcts[index]);
        rightPanel.add(dashCovStats[index]);

        row.add(name, BorderLayout.WEST);
        row.add(barTrack, BorderLayout.CENTER);
        row.add(rightPanel, BorderLayout.EAST);

        row.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        row.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (mainTabs != null) {
                    mainTabs.setSelectedIndex(1);
                    rawHeaderCombo.setSelectedIndex(idx + 3);
                }
            }
            @Override public void mouseEntered(MouseEvent e) { row.setBackground(BG2); }
            @Override public void mouseExited(MouseEvent e) { row.setBackground(BG_ELEV); }
        });

        return row;
    }

    private JLabel dashSectionLabel(String text) {
        JLabel l = new JLabel("  " + text);
        l.setFont(new Font("SansSerif", Font.BOLD, 13));
        l.setForeground(ACCENT);
        l.setOpaque(true);
        l.setBackground(BG2);
        l.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 3, 0, 0, ACCENT),
                new EmptyBorder(5, 10, 5, 10)));
        l.setAlignmentX(Component.LEFT_ALIGNMENT);
        l.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        return l;
    }

    public void refreshDashboard() {
        List<HeaderResult> all = resultStore.getAll();
        int total = all.size();

        Set<String> hosts = new HashSet<>();
        Set<String> endpoints = new HashSet<>();
        int missingTotal = 0;
        int hstsP = 0, ccP = 0, xfoP = 0, xctoP = 0, acaoP = 0, cspP = 0;

        for (HeaderResult r : all) {
            hosts.add(r.host());
            endpoints.add(r.endpointKey());
            missingTotal += r.missingCount();
            if (r.hstsPresent()) hstsP++;
            if (r.cacheControlPresent()) ccP++;
            if (r.xfoPresent() || r.xfoCoveredByCsp()) xfoP++;
            if (r.xctoPresent()) xctoP++;
            if (r.acaoPresent()) acaoP++;
            if (r.cspPresent()) cspP++;
        }

        List<TestcaseResult> tcAll = tcResultStore.getAll();
        long tcErrors = tcAll.stream().filter(r ->
                r.status() == ResultStatus.ERROR || r.status() == ResultStatus.INCONCLUSIVE).count();

        dashHosts.setText(String.valueOf(hosts.size()));
        dashEndpoints.setText(String.valueOf(endpoints.size()));
        dashAssessed.setText(String.valueOf(total));
        dashTestcases.setText(String.valueOf(tcAll.size()));
        dashMissing.setText(String.valueOf(missingTotal));
        dashErrors.setText(String.valueOf(tcErrors));

        int[] present = {hstsP, ccP, xfoP, xctoP, acaoP, cspP};
        for (int i = 0; i < 6; i++) {
            dashCovPresent[i] = present[i];
            dashCovTotal[i] = total;
            int pct = total > 0 ? present[i] * 100 / total : 0;
            dashCovPcts[i].setText(pct + "%");
            dashCovStats[i].setText(present[i] + " / " + total);
            dashCovBars[i].repaint();
        }

        // Security Posture
        int totalChecks = total * 6;
        int passedChecks = hstsP + ccP + xfoP + xctoP + acaoP + cspP;
        int affected = 0;
        int compliant = 0;
        for (HeaderResult r : all) {
            if (r.hasAnyMissing()) {
                affected++;
            } else {
                compliant++;
            }
        }
        // Deduplicate by endpoint key
        Map<String, Boolean> endpointCompliance = new HashMap<>();
        for (HeaderResult r : all) {
            String key = r.endpointKey();
            boolean missing = r.hasAnyMissing();
            Boolean prev = endpointCompliance.get(key);
            if (prev == null) {
                endpointCompliance.put(key, missing);
            } else if (missing) {
                endpointCompliance.put(key, true);
            }
        }
        int affectedEps = 0, compliantEps = 0;
        for (boolean hasMissing : endpointCompliance.values()) {
            if (hasMissing) affectedEps++;
            else compliantEps++;
        }
        int noHeaderEps = 0;
        Map<String, Boolean> endpointAllMissing = new HashMap<>();
        for (HeaderResult r : all) {
            String key = r.endpointKey();
            boolean allMissing = r.missingCount() == 6;
            Boolean prev = endpointAllMissing.get(key);
            if (prev == null) {
                endpointAllMissing.put(key, allMissing);
            } else if (!allMissing) {
                endpointAllMissing.put(key, false);
            }
        }
        for (boolean allMissing : endpointAllMissing.values()) {
            if (allMissing) noHeaderEps++;
        }
        dashAffected.setText(String.valueOf(affectedEps));
        dashCompliant.setText(String.valueOf(compliantEps));
        dashNoHeaders.setText(String.valueOf(noHeaderEps));
        dashCompliance.setText(totalChecks > 0
                ? String.format("%.1f%%", passedChecks * 100.0 / totalChecks)
                : "—");

        if (healthTracker != null) {
            dashProcessed.setText(String.valueOf(healthTracker.requestsProcessed()));
            dashChecksMin.setText(String.format("%.1f", healthTracker.checksPerMinute()));
            long heapUsed = healthTracker.heapUsedMB();
            long heapMax = healthTracker.heapMaxMB();
            dashHeap.setText(heapMax > 0 ? heapUsed + " / " + heapMax + " MB" : heapUsed + " MB");
            dashElapsed.setText(healthTracker.elapsedTime());
            dashLastUpdate.setText(healthTracker.timeSinceLastProgress());
            dashTcErrors.setText(String.valueOf(healthTracker.scanErrors()));
        }
    }

    // ─── Raw Results Panel (with embedded filter bar) ────────────────────────

    private JPanel createRawResultsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG);
        panel.setBorder(new EmptyBorder(6, 10, 6, 10));

        // Filter bar
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bar.setBackground(BG2);
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER),
                new EmptyBorder(6, 14, 6, 14)));

        rawSearchField = darkField(14);
        rawSearchField.setToolTipText("Search host/path");
        rawSearchField.addActionListener(e -> applyRawFilters());
        bar.add(label("Search")); bar.add(rawSearchField);

        rawHostCombo = darkCombo(new String[]{"None"});
        rawHostCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyRawFilters(); });
        bar.add(label("Host")); bar.add(rawHostCombo);

        rawStatusCombo = darkCombo(new String[]{"None"});
        rawStatusCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyRawFilters(); });
        bar.add(label("Status Code")); bar.add(rawStatusCombo);

        rawHeaderCombo = darkCombo(new String[]{
                "None", "Any Missing", "All Missing", "HSTS Missing", "Cache-Control Missing",
                "XFO Missing", "XCTO Missing", "ACAO Missing", "CSP Missing"});
        rawHeaderCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyRawFilters(); });
        bar.add(label("Header")); bar.add(rawHeaderCombo);

        JButton clearFilt = pill("Reset", new Color(60, 64, 76), new Color(75, 80, 94));
        clearFilt.addActionListener(e -> clearRawFilters());
        bar.add(clearFilt);

        rawFilterIndicator = new JLabel("");
        rawFilterIndicator.setFont(new Font("SansSerif", Font.PLAIN, 12));
        rawFilterIndicator.setForeground(ACCENT);
        bar.add(rawFilterIndicator);

        // Table
        JTable table = new JTable(rawTableModel);
        styleTable(table);
        applyPresenceRenderer(table, 4, 7);
        applyAcaoPresenceRenderer(table, 8);
        applyPresenceRenderer(table, 10, 10);
        applyCenterRenderer(table, 1);
        applyCenterRenderer(table, 3);
        applyAcaoChecksRenderer(table, 9);

        JScrollPane tableSp = new JScrollPane(table);
        tableSp.setBorder(BorderFactory.createLineBorder(BORDER));
        tableSp.getViewport().setBackground(TBL_EVEN);
        tableSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        tableSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());

        // Request/Response detail
        JTextArea requestArea = darkTextArea();
        JTextArea responseArea = darkTextArea();

        JPanel reqPanel = new JPanel(new BorderLayout());
        reqPanel.setBackground(BG);
        JLabel reqLabel = new JLabel("  REQUEST");
        reqLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        reqLabel.setForeground(ACCENT);
        reqLabel.setOpaque(true);
        reqLabel.setBackground(BG2);
        reqLabel.setBorder(new EmptyBorder(4, 8, 4, 8));

        JScrollPane reqSp = new JScrollPane(requestArea);
        reqSp.setBorder(BorderFactory.createLineBorder(BORDER));
        reqSp.getViewport().setBackground(BG_INPUT);
        reqSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        reqSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());
        reqPanel.add(reqLabel, BorderLayout.NORTH);
        reqPanel.add(reqSp, BorderLayout.CENTER);

        JPanel respPanel = new JPanel(new BorderLayout());
        respPanel.setBackground(BG);
        JLabel respLabel = new JLabel("  RESPONSE");
        respLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        respLabel.setForeground(TXT2);
        respLabel.setOpaque(true);
        respLabel.setBackground(BG2);
        respLabel.setBorder(new EmptyBorder(4, 8, 4, 8));
        JScrollPane respSp = new JScrollPane(responseArea);
        respSp.setBorder(BorderFactory.createLineBorder(BORDER));
        respSp.getViewport().setBackground(BG_INPUT);
        respSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        respSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());
        respPanel.add(respLabel, BorderLayout.NORTH);
        respPanel.add(respSp, BorderLayout.CENTER);

        JSplitPane reqRespSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, respPanel);
        reqRespSplit.setResizeWeight(0.5);
        reqRespSplit.setDividerSize(4);
        reqRespSplit.setBackground(BG);
        reqRespSplit.setBorder(null);

        JPanel detailWrapper = new JPanel(new BorderLayout());
        detailWrapper.setBackground(BG);

        JPanel detailHeaderBar = new JPanel(new BorderLayout());
        detailHeaderBar.setBackground(BG2);
        detailHeaderBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER),
                new EmptyBorder(2, 12, 2, 4)));

        JLabel detailTitle = new JLabel("  Request / Response");
        detailTitle.setFont(new Font("SansSerif", Font.PLAIN, 12));
        detailTitle.setForeground(TXT_M);

        JButton closeDetailBtn = new JButton("✕");
        closeDetailBtn.setFont(new Font("SansSerif", Font.PLAIN, 15));
        closeDetailBtn.setForeground(TXT_M);
        closeDetailBtn.setBackground(BG2);
        closeDetailBtn.setFocusPainted(false);
        closeDetailBtn.setBorderPainted(false);
        closeDetailBtn.setContentAreaFilled(false);
        closeDetailBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        closeDetailBtn.setBorder(new EmptyBorder(2, 10, 2, 10));
        closeDetailBtn.setToolTipText("Close viewer");
        closeDetailBtn.addMouseListener(new MouseAdapter() {
            @Override public void mouseEntered(MouseEvent e) { closeDetailBtn.setForeground(RED_FG); }
            @Override public void mouseExited(MouseEvent e) { closeDetailBtn.setForeground(TXT_M); }
        });

        detailHeaderBar.add(detailTitle, BorderLayout.WEST);
        detailHeaderBar.add(closeDetailBtn, BorderLayout.EAST);

        detailWrapper.add(detailHeaderBar, BorderLayout.NORTH);
        detailWrapper.add(reqRespSplit, BorderLayout.CENTER);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableSp, detailWrapper);
        mainSplit.setResizeWeight(0.55);
        mainSplit.setDividerSize(5);
        mainSplit.setBackground(BG);
        mainSplit.setBorder(null);

        JPanel contentWrapper = new JPanel(new BorderLayout());
        contentWrapper.setBackground(BG);
        contentWrapper.add(tableSp, BorderLayout.CENTER);
        final boolean[] detailShown = {false};

        closeDetailBtn.addActionListener(ev -> {
            table.clearSelection();
            requestArea.setText("");
            responseArea.setText("");
            reqLabel.setText("  REQUEST");
            respLabel.setText("  RESPONSE");
            if (detailShown[0]) {
                contentWrapper.removeAll();
                contentWrapper.add(tableSp, BorderLayout.CENTER);
                contentWrapper.revalidate();
                contentWrapper.repaint();
                detailShown[0] = false;
            }
        });

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                requestArea.setText("");
                responseArea.setText("");
                reqLabel.setText("  REQUEST");
                respLabel.setText("  RESPONSE");
                if (detailShown[0]) {
                    contentWrapper.removeAll();
                    contentWrapper.add(tableSp, BorderLayout.CENTER);
                    contentWrapper.revalidate();
                    contentWrapper.repaint();
                    detailShown[0] = false;
                }
                return;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            List<HeaderResult> data = rawTableModel.getData();
            if (modelRow < 0 || modelRow >= data.size()) return;

            HeaderResult r = data.get(modelRow);

            String reqText = r.rawRequest();
            String respText = headersOnly(r.rawResponse());
            requestArea.setText(reqText != null ? reqText : "(No request data captured)");
            responseArea.setText(respText != null ? respText : "(No response data captured)");
            requestArea.setCaretPosition(0);
            responseArea.setCaretPosition(0);

            if (!detailShown[0]) {
                contentWrapper.removeAll();
                mainSplit.setTopComponent(tableSp);
                mainSplit.setBottomComponent(detailWrapper);
                contentWrapper.add(mainSplit, BorderLayout.CENTER);
                contentWrapper.revalidate();
                contentWrapper.repaint();
                SwingUtilities.invokeLater(() -> mainSplit.setDividerLocation(0.55));
                detailShown[0] = true;
            }
            table.requestFocusInWindow();
        });

        addDetailArrowNav(table, requestArea, responseArea);

        panel.add(bar, BorderLayout.NORTH);
        panel.add(contentWrapper, BorderLayout.CENTER);
        return panel;
    }

    // ─── Host Summary Panel ─────────────────────────────────────────────────

    private JPanel createHostSummaryPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG);
        panel.setBorder(new EmptyBorder(6, 10, 6, 10));

        // Filter bar
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bar.setBackground(BG2);
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER),
                new EmptyBorder(6, 14, 6, 14)));

        hostSearchField = darkField(14);
        hostSearchField.setToolTipText("Search host");
        hostSearchField.addActionListener(e -> applyHostFilters());
        bar.add(label("Search")); bar.add(hostSearchField);

        hostHeaderCombo = darkCombo(new String[]{
                "None", "All Missing", "HSTS Missing", "Cache-Control Missing",
                "XFO Missing", "XCTO Missing", "ACAO Missing", "CSP Missing"});
        hostHeaderCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyHostFilters(); });
        bar.add(label("Header")); bar.add(hostHeaderCombo);

        JButton clearBtn = pill("Reset", new Color(60, 64, 76), new Color(75, 80, 94));
        clearBtn.addActionListener(e -> {
            hostSearchField.setText("");
            hostHeaderCombo.setSelectedIndex(0);
            applyHostFilters();
        });
        bar.add(clearBtn);

        hostFilterIndicator = new JLabel("");
        hostFilterIndicator.setFont(new Font("SansSerif", Font.PLAIN, 12));
        hostFilterIndicator.setForeground(ACCENT);
        bar.add(hostFilterIndicator);

        JTable table = new JTable(hostTableModel);
        styleTable(table);
        applyCountRenderer(table, 2, 8);
        table.getColumnModel().getColumn(1).setCellRenderer(new javax.swing.table.DefaultTableCellRenderer() {
            { setHorizontalAlignment(javax.swing.SwingConstants.CENTER); }
            @Override public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean foc, int row, int col) {
                super.getTableCellRendererComponent(t, val, sel, foc, row, col);
                setBackground(sel ? TBL_SEL : (row % 2 == 0 ? TBL_EVEN : TBL_ODD));
                setForeground(TXT);
                return this;
            }
        });

        JScrollPane sp = new JScrollPane(table);
        sp.setBorder(BorderFactory.createLineBorder(BORDER));
        sp.getViewport().setBackground(TBL_EVEN);
        sp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        sp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());

        panel.add(bar, BorderLayout.NORTH);
        panel.add(sp, BorderLayout.CENTER);
        return panel;
    }

    // ─── Endpoint Summary Panel (with request/response detail) ──────────────

    private JPanel createEndpointSummaryPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG);
        panel.setBorder(new EmptyBorder(6, 10, 6, 10));

        // Filter bar
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bar.setBackground(BG2);
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER),
                new EmptyBorder(6, 14, 6, 14)));

        epSearchField = darkField(14);
        epSearchField.setToolTipText("Search host/path");
        epSearchField.addActionListener(e -> applyEpFilters());
        bar.add(label("Search")); bar.add(epSearchField);

        epHostCombo = darkCombo(new String[]{"None"});
        epHostCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyEpFilters(); });
        bar.add(label("Host")); bar.add(epHostCombo);

        epHeaderCombo = darkCombo(new String[]{
                "None", "Any Missing", "All Missing", "HSTS Missing", "Cache-Control Missing",
                "XFO Missing", "XCTO Missing", "ACAO Missing", "CSP Missing"});
        epHeaderCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyEpFilters(); });
        bar.add(label("Header")); bar.add(epHeaderCombo);

        JButton clearBtn = pill("Reset", new Color(60, 64, 76), new Color(75, 80, 94));
        clearBtn.addActionListener(e -> {
            epSearchField.setText("");
            epHostCombo.setSelectedIndex(0);
            epHeaderCombo.setSelectedIndex(0);
            applyEpFilters();
        });
        bar.add(clearBtn);

        epFilterIndicator = new JLabel("");
        epFilterIndicator.setFont(new Font("SansSerif", Font.PLAIN, 12));
        epFilterIndicator.setForeground(ACCENT);
        bar.add(epFilterIndicator);

        JTable table = new JTable(epTableModel);
        styleTable(table);
        applyCountRenderer(table, 5, 10);
        applyCenterRenderer(table, 1);
        applyCenterRenderer(table, 3);
        applyCenterRenderer(table, 4);
        applyCenterRenderer(table, 11);
        applyCenterRenderer(table, 12);
        applyCenterRenderer(table, 13);

        JScrollPane tableSp = new JScrollPane(table);
        tableSp.setBorder(BorderFactory.createLineBorder(BORDER));
        tableSp.getViewport().setBackground(TBL_EVEN);
        tableSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        tableSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());

        // Request/Response detail
        JTextArea requestArea = darkTextArea();
        JTextArea responseArea = darkTextArea();

        JPanel reqPanel = new JPanel(new BorderLayout());
        reqPanel.setBackground(BG);
        JLabel reqLabel = new JLabel("  REQUEST");
        reqLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        reqLabel.setForeground(ACCENT);
        reqLabel.setOpaque(true);
        reqLabel.setBackground(BG2);
        reqLabel.setBorder(new EmptyBorder(4, 8, 4, 8));

        JScrollPane reqSp = new JScrollPane(requestArea);
        reqSp.setBorder(BorderFactory.createLineBorder(BORDER));
        reqSp.getViewport().setBackground(BG_INPUT);
        reqSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        reqSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());
        reqPanel.add(reqLabel, BorderLayout.NORTH);
        reqPanel.add(reqSp, BorderLayout.CENTER);

        JPanel respPanel = new JPanel(new BorderLayout());
        respPanel.setBackground(BG);
        JLabel respLabel = new JLabel("  RESPONSE");
        respLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        respLabel.setForeground(TXT2);
        respLabel.setOpaque(true);
        respLabel.setBackground(BG2);
        respLabel.setBorder(new EmptyBorder(4, 8, 4, 8));
        JScrollPane respSp = new JScrollPane(responseArea);
        respSp.setBorder(BorderFactory.createLineBorder(BORDER));
        respSp.getViewport().setBackground(BG_INPUT);
        respSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        respSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());
        respPanel.add(respLabel, BorderLayout.NORTH);
        respPanel.add(respSp, BorderLayout.CENTER);

        JSplitPane reqRespSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, respPanel);
        reqRespSplit.setResizeWeight(0.5);
        reqRespSplit.setDividerSize(4);
        reqRespSplit.setBackground(BG);
        reqRespSplit.setBorder(null);

        JPanel detailWrapper = new JPanel(new BorderLayout());
        detailWrapper.setBackground(BG);

        JPanel detailHeaderBar = new JPanel(new BorderLayout());
        detailHeaderBar.setBackground(BG2);
        detailHeaderBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER),
                new EmptyBorder(2, 12, 2, 4)));

        JLabel detailTitle = new JLabel("  Request / Response (most recent for endpoint)");
        detailTitle.setFont(new Font("SansSerif", Font.PLAIN, 12));
        detailTitle.setForeground(TXT_M);

        JButton closeDetailBtn = new JButton("✕");
        closeDetailBtn.setFont(new Font("SansSerif", Font.PLAIN, 15));
        closeDetailBtn.setForeground(TXT_M);
        closeDetailBtn.setBackground(BG2);
        closeDetailBtn.setFocusPainted(false);
        closeDetailBtn.setBorderPainted(false);
        closeDetailBtn.setContentAreaFilled(false);
        closeDetailBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        closeDetailBtn.setBorder(new EmptyBorder(2, 10, 2, 10));
        closeDetailBtn.setToolTipText("Close viewer");
        closeDetailBtn.addMouseListener(new MouseAdapter() {
            @Override public void mouseEntered(MouseEvent e) { closeDetailBtn.setForeground(RED_FG); }
            @Override public void mouseExited(MouseEvent e) { closeDetailBtn.setForeground(TXT_M); }
        });

        detailHeaderBar.add(detailTitle, BorderLayout.WEST);
        detailHeaderBar.add(closeDetailBtn, BorderLayout.EAST);

        detailWrapper.add(detailHeaderBar, BorderLayout.NORTH);
        detailWrapper.add(reqRespSplit, BorderLayout.CENTER);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableSp, detailWrapper);
        mainSplit.setResizeWeight(0.55);
        mainSplit.setDividerSize(5);
        mainSplit.setBackground(BG);
        mainSplit.setBorder(null);

        JPanel contentWrapper = new JPanel(new BorderLayout());
        contentWrapper.setBackground(BG);
        contentWrapper.add(tableSp, BorderLayout.CENTER);
        final boolean[] detailShown = {false};

        closeDetailBtn.addActionListener(ev -> {
            table.clearSelection();
            requestArea.setText("");
            responseArea.setText("");
            reqLabel.setText("  REQUEST");
            respLabel.setText("  RESPONSE");
            if (detailShown[0]) {
                contentWrapper.removeAll();
                contentWrapper.add(tableSp, BorderLayout.CENTER);
                contentWrapper.revalidate();
                contentWrapper.repaint();
                detailShown[0] = false;
            }
        });

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                requestArea.setText("");
                responseArea.setText("");
                reqLabel.setText("  REQUEST");
                respLabel.setText("  RESPONSE");
                if (detailShown[0]) {
                    contentWrapper.removeAll();
                    contentWrapper.add(tableSp, BorderLayout.CENTER);
                    contentWrapper.revalidate();
                    contentWrapper.repaint();
                    detailShown[0] = false;
                }
                return;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            List<EndpointSummary> data = epTableModel.getData();
            if (modelRow < 0 || modelRow >= data.size()) return;

            EndpointSummary ep = data.get(modelRow);
            String epKey = ep.host() + ":" + ep.port() + ":" + ep.method() + ":" + ep.pathAndQuery();

            HeaderResult match = null;
            List<HeaderResult> all = resultStore.getAll();
            for (int i = all.size() - 1; i >= 0; i--) {
                if (all.get(i).endpointKey().equals(epKey)) {
                    match = all.get(i);
                    break;
                }
            }

            if (match != null) {
                String reqText = match.rawRequest();
                String respText = headersOnly(match.rawResponse());
                requestArea.setText(reqText != null ? reqText : "(No request data captured)");
                responseArea.setText(respText != null ? respText : "(No response data captured)");
            } else {
                requestArea.setText("(No matching result found)");
                responseArea.setText("(No matching result found)");
            }
            requestArea.setCaretPosition(0);
            responseArea.setCaretPosition(0);

            if (!detailShown[0]) {
                contentWrapper.removeAll();
                mainSplit.setTopComponent(tableSp);
                mainSplit.setBottomComponent(detailWrapper);
                contentWrapper.add(mainSplit, BorderLayout.CENTER);
                contentWrapper.revalidate();
                contentWrapper.repaint();
                SwingUtilities.invokeLater(() -> mainSplit.setDividerLocation(0.55));
                detailShown[0] = true;
            }
            table.requestFocusInWindow();
        });

        addDetailArrowNav(table, requestArea, responseArea);

        panel.add(bar, BorderLayout.NORTH);
        panel.add(contentWrapper, BorderLayout.CENTER);
        return panel;
    }

    // ─── Testcase Results Panel ──────────────────────────────────────────────

    private JPanel createTestcasePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG);
        panel.setBorder(new EmptyBorder(6, 10, 6, 10));

        // Testcase filter bar
        JPanel tcFilterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        tcFilterBar.setBackground(BG2);
        tcFilterBar.setBorder(new EmptyBorder(4, 8, 4, 8));

        tcPathField = darkField(14);
        tcPathField.setToolTipText("Search path (substring match)");
        tcPathField.addActionListener(e -> applyTcFilters());

        tcHostCombo = darkCombo(new String[]{"None"});
        tcHostCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyTcFilters(); });
        tcModeCombo = darkCombo(new String[]{"None", "PASSIVE", "ACTIVE"});
        tcModeCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyTcFilters(); });
        tcStatusCombo = darkCombo(new String[]{"None", "PASS", "FAIL", "ERROR", "INCONCLUSIVE", "NOT_TESTED"});
        tcStatusCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyTcFilters(); });
        tcCategoryCombo = darkCombo(new String[]{"None"});
        tcCategoryCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyTcFilters(); });

        tcFilterBar.add(label("Path")); tcFilterBar.add(tcPathField);
        tcFilterBar.add(label("Host")); tcFilterBar.add(tcHostCombo);
        tcFilterBar.add(label("Mode")); tcFilterBar.add(tcModeCombo);
        tcFilterBar.add(label("Result")); tcFilterBar.add(tcStatusCombo);
        tcFilterBar.add(label("Category")); tcFilterBar.add(tcCategoryCombo);

        JButton tcClear = pill("Reset", new Color(60, 64, 76), new Color(75, 80, 94));
        tcClear.addActionListener(e -> {
            tcPathField.setText("");
            tcHostCombo.setSelectedIndex(0);
            tcModeCombo.setSelectedIndex(0);
            tcStatusCombo.setSelectedIndex(0);
            tcCategoryCombo.setSelectedIndex(0);
            applyTcFilters();
        });
        tcFilterBar.add(tcClear);

        JTable table = new JTable(tcTableModel);
        styleTable(table);
        applyTestcaseHeaderRenderer(table, 6, 10);
        applyTestcaseHeaderRenderer(table, 12, 12);
        applyTcAcaoChecksRenderer(table, 11);
        applyCenterRenderer(table, 4);
        applyCenterRenderer(table, 5);

        JScrollPane tableSp = new JScrollPane(table);
        tableSp.setBorder(BorderFactory.createLineBorder(BORDER));
        tableSp.getViewport().setBackground(TBL_EVEN);
        tableSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        tableSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());

        // Request/Response detail panel
        JTextArea requestArea = darkTextArea();
        JTextArea responseArea = darkTextArea();

        JPanel reqPanel = new JPanel(new BorderLayout());
        reqPanel.setBackground(BG);
        JLabel reqLabel = new JLabel("  REQUEST");
        reqLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        reqLabel.setForeground(ACCENT);
        reqLabel.setOpaque(true);
        reqLabel.setBackground(BG2);
        reqLabel.setBorder(new EmptyBorder(4, 8, 4, 8));

        JScrollPane reqSp = new JScrollPane(requestArea);
        reqSp.setBorder(BorderFactory.createLineBorder(BORDER));
        reqSp.getViewport().setBackground(BG_INPUT);
        reqSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        reqSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());
        reqPanel.add(reqLabel, BorderLayout.NORTH);
        reqPanel.add(reqSp, BorderLayout.CENTER);

        JPanel respPanel = new JPanel(new BorderLayout());
        respPanel.setBackground(BG);
        JLabel respLabel = new JLabel("  RESPONSE");
        respLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        respLabel.setForeground(TXT2);
        respLabel.setOpaque(true);
        respLabel.setBackground(BG2);
        respLabel.setBorder(new EmptyBorder(4, 8, 4, 8));
        JScrollPane respSp = new JScrollPane(responseArea);
        respSp.setBorder(BorderFactory.createLineBorder(BORDER));
        respSp.getViewport().setBackground(BG_INPUT);
        respSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        respSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());
        respPanel.add(respLabel, BorderLayout.NORTH);
        respPanel.add(respSp, BorderLayout.CENTER);

        JSplitPane reqRespSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, respPanel);
        reqRespSplit.setResizeWeight(0.5);
        reqRespSplit.setDividerSize(4);
        reqRespSplit.setBackground(BG);
        reqRespSplit.setBorder(null);

        // Detail wrapper with subtle close bar
        JPanel detailWrapper = new JPanel(new BorderLayout());
        detailWrapper.setBackground(BG);

        JPanel detailHeaderBar = new JPanel(new BorderLayout());
        detailHeaderBar.setBackground(BG2);
        detailHeaderBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER),
                new EmptyBorder(2, 12, 2, 4)));

        JLabel detailTitle = new JLabel("  Request / Response");
        detailTitle.setFont(new Font("SansSerif", Font.PLAIN, 12));
        detailTitle.setForeground(TXT_M);

        JButton closeDetailBtn = new JButton("✕");
        closeDetailBtn.setFont(new Font("SansSerif", Font.PLAIN, 15));
        closeDetailBtn.setForeground(TXT_M);
        closeDetailBtn.setBackground(BG2);
        closeDetailBtn.setFocusPainted(false);
        closeDetailBtn.setBorderPainted(false);
        closeDetailBtn.setContentAreaFilled(false);
        closeDetailBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        closeDetailBtn.setBorder(new EmptyBorder(2, 10, 2, 10));
        closeDetailBtn.setToolTipText("Close viewer");
        closeDetailBtn.addMouseListener(new MouseAdapter() {
            @Override public void mouseEntered(MouseEvent e) { closeDetailBtn.setForeground(RED_FG); }
            @Override public void mouseExited(MouseEvent e) { closeDetailBtn.setForeground(TXT_M); }
        });

        detailHeaderBar.add(detailTitle, BorderLayout.WEST);
        detailHeaderBar.add(closeDetailBtn, BorderLayout.EAST);

        detailWrapper.add(detailHeaderBar, BorderLayout.NORTH);
        detailWrapper.add(reqRespSplit, BorderLayout.CENTER);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableSp, detailWrapper);
        mainSplit.setResizeWeight(0.55);
        mainSplit.setDividerSize(5);
        mainSplit.setBackground(BG);
        mainSplit.setBorder(null);

        JPanel contentWrapper = new JPanel(new BorderLayout());
        contentWrapper.setBackground(BG);
        contentWrapper.add(tableSp, BorderLayout.CENTER);
        final boolean[] detailShown = {false};

        closeDetailBtn.addActionListener(ev -> {
            table.clearSelection();
            requestArea.setText("");
            responseArea.setText("");
            reqLabel.setText("  REQUEST");
            respLabel.setText("  RESPONSE");
            if (detailShown[0]) {
                contentWrapper.removeAll();
                contentWrapper.add(tableSp, BorderLayout.CENTER);
                contentWrapper.revalidate();
                contentWrapper.repaint();
                detailShown[0] = false;
            }
        });

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                requestArea.setText("");
                responseArea.setText("");
                reqLabel.setText("  REQUEST");
                respLabel.setText("  RESPONSE");
                if (detailShown[0]) {
                    contentWrapper.removeAll();
                    contentWrapper.add(tableSp, BorderLayout.CENTER);
                    contentWrapper.revalidate();
                    contentWrapper.repaint();
                    detailShown[0] = false;
                }
                return;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            List<TestcaseResult> data = tcTableModel.getData();
            if (modelRow < 0 || modelRow >= data.size()) return;

            TestcaseResult r = data.get(modelRow);

            String reqText = r.requestData();
            String respText = headersOnly(r.responseData());
            requestArea.setText(reqText != null ? reqText : "(No request data captured)");
            responseArea.setText(respText != null ? respText : "(No response data captured)");
            requestArea.setCaretPosition(0);
            responseArea.setCaretPosition(0);

            if (!detailShown[0]) {
                contentWrapper.removeAll();
                mainSplit.setTopComponent(tableSp);
                mainSplit.setBottomComponent(detailWrapper);
                contentWrapper.add(mainSplit, BorderLayout.CENTER);
                contentWrapper.revalidate();
                contentWrapper.repaint();
                SwingUtilities.invokeLater(() -> mainSplit.setDividerLocation(0.55));
                detailShown[0] = true;
            }
            table.requestFocusInWindow();
        });

        addDetailArrowNav(table, requestArea, responseArea);

        panel.add(tcFilterBar, BorderLayout.NORTH);
        panel.add(contentWrapper, BorderLayout.CENTER);
        return panel;
    }

    // ─── Repeater Requests Panel ─────────────────────────────────────────────

    private JPanel createRepeaterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG);
        panel.setBorder(new EmptyBorder(6, 10, 6, 10));

        // Filter bar
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bar.setBackground(BG2);
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER),
                new EmptyBorder(6, 14, 6, 14)));

        repSearchField = darkField(14);
        repSearchField.setToolTipText("Search host/path");
        repSearchField.addActionListener(e -> applyRepeaterFilters());
        bar.add(label("Search")); bar.add(repSearchField);

        repHostCombo = darkCombo(new String[]{"None"});
        repHostCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyRepeaterFilters(); });
        bar.add(label("Host")); bar.add(repHostCombo);

        repStatusCombo = darkCombo(new String[]{"None"});
        repStatusCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyRepeaterFilters(); });
        bar.add(label("Status Code")); bar.add(repStatusCombo);

        repHeaderCombo = darkCombo(new String[]{
                "None", "Any Missing", "All Missing", "HSTS Missing", "Cache-Control Missing",
                "XFO Missing", "XCTO Missing", "ACAO Missing", "CSP Missing"});
        repHeaderCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyRepeaterFilters(); });
        bar.add(label("Header")); bar.add(repHeaderCombo);

        JButton clearFilt = pill("Reset", new Color(60, 64, 76), new Color(75, 80, 94));
        clearFilt.addActionListener(e -> clearRepeaterFilters());
        bar.add(clearFilt);

        repFilterIndicator = new JLabel("");
        repFilterIndicator.setFont(new Font("SansSerif", Font.PLAIN, 12));
        repFilterIndicator.setForeground(ACCENT);
        bar.add(repFilterIndicator);

        JLabel info = new JLabel("  Header status only — no testcases");
        info.setFont(new Font("SansSerif", Font.PLAIN, 12));
        info.setForeground(TXT_M);
        bar.add(Box.createHorizontalStrut(8));
        bar.add(info);

        // Table
        JTable table = new JTable(repeaterTableModel);
        styleTable(table);
        applyPresenceRenderer(table, 4, 7);
        applyAcaoPresenceRenderer(table, 8);
        applyPresenceRenderer(table, 10, 10);
        applyCenterRenderer(table, 1);
        applyCenterRenderer(table, 3);
        applyAcaoChecksRenderer(table, 9);

        JScrollPane tableSp = new JScrollPane(table);
        tableSp.setBorder(BorderFactory.createLineBorder(BORDER));
        tableSp.getViewport().setBackground(TBL_EVEN);
        tableSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        tableSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());

        // Request/Response detail
        JTextArea requestArea = darkTextArea();
        JTextArea responseArea = darkTextArea();

        JPanel reqPanel = new JPanel(new BorderLayout());
        reqPanel.setBackground(BG);
        JLabel reqLabel = new JLabel("  REQUEST");
        reqLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        reqLabel.setForeground(ACCENT);
        reqLabel.setOpaque(true);
        reqLabel.setBackground(BG2);
        reqLabel.setBorder(new EmptyBorder(4, 8, 4, 8));

        JScrollPane reqSp = new JScrollPane(requestArea);
        reqSp.setBorder(BorderFactory.createLineBorder(BORDER));
        reqSp.getViewport().setBackground(BG_INPUT);
        reqSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        reqSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());
        reqPanel.add(reqLabel, BorderLayout.NORTH);
        reqPanel.add(reqSp, BorderLayout.CENTER);

        JPanel respPanel = new JPanel(new BorderLayout());
        respPanel.setBackground(BG);
        JLabel respLabel = new JLabel("  RESPONSE");
        respLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        respLabel.setForeground(TXT2);
        respLabel.setOpaque(true);
        respLabel.setBackground(BG2);
        respLabel.setBorder(new EmptyBorder(4, 8, 4, 8));
        JScrollPane respSp = new JScrollPane(responseArea);
        respSp.setBorder(BorderFactory.createLineBorder(BORDER));
        respSp.getViewport().setBackground(BG_INPUT);
        respSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        respSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());
        respPanel.add(respLabel, BorderLayout.NORTH);
        respPanel.add(respSp, BorderLayout.CENTER);

        JSplitPane reqRespSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, respPanel);
        reqRespSplit.setResizeWeight(0.5);
        reqRespSplit.setDividerSize(4);
        reqRespSplit.setBackground(BG);
        reqRespSplit.setBorder(null);

        // Detail wrapper with subtle close bar
        JPanel detailWrapper = new JPanel(new BorderLayout());
        detailWrapper.setBackground(BG);

        JPanel detailHeaderBar = new JPanel(new BorderLayout());
        detailHeaderBar.setBackground(BG2);
        detailHeaderBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER),
                new EmptyBorder(2, 12, 2, 4)));

        JLabel detailTitle = new JLabel("  Request / Response");
        detailTitle.setFont(new Font("SansSerif", Font.PLAIN, 12));
        detailTitle.setForeground(TXT_M);

        JButton closeDetailBtn = new JButton("✕");
        closeDetailBtn.setFont(new Font("SansSerif", Font.PLAIN, 15));
        closeDetailBtn.setForeground(TXT_M);
        closeDetailBtn.setBackground(BG2);
        closeDetailBtn.setFocusPainted(false);
        closeDetailBtn.setBorderPainted(false);
        closeDetailBtn.setContentAreaFilled(false);
        closeDetailBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        closeDetailBtn.setBorder(new EmptyBorder(2, 10, 2, 10));
        closeDetailBtn.setToolTipText("Close viewer");
        closeDetailBtn.addMouseListener(new MouseAdapter() {
            @Override public void mouseEntered(MouseEvent e) { closeDetailBtn.setForeground(RED_FG); }
            @Override public void mouseExited(MouseEvent e) { closeDetailBtn.setForeground(TXT_M); }
        });

        detailHeaderBar.add(detailTitle, BorderLayout.WEST);
        detailHeaderBar.add(closeDetailBtn, BorderLayout.EAST);

        detailWrapper.add(detailHeaderBar, BorderLayout.NORTH);
        detailWrapper.add(reqRespSplit, BorderLayout.CENTER);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableSp, detailWrapper);
        mainSplit.setResizeWeight(0.55);
        mainSplit.setDividerSize(5);
        mainSplit.setBackground(BG);
        mainSplit.setBorder(null);

        JPanel contentWrapper = new JPanel(new BorderLayout());
        contentWrapper.setBackground(BG);
        contentWrapper.add(tableSp, BorderLayout.CENTER);
        final boolean[] detailShown = {false};

        closeDetailBtn.addActionListener(ev -> {
            table.clearSelection();
            requestArea.setText("");
            responseArea.setText("");
            reqLabel.setText("  REQUEST");
            respLabel.setText("  RESPONSE");
            if (detailShown[0]) {
                contentWrapper.removeAll();
                contentWrapper.add(tableSp, BorderLayout.CENTER);
                contentWrapper.revalidate();
                contentWrapper.repaint();
                detailShown[0] = false;
            }
        });

        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            int viewRow = table.getSelectedRow();
            if (viewRow < 0) {
                requestArea.setText("");
                responseArea.setText("");
                reqLabel.setText("  REQUEST");
                respLabel.setText("  RESPONSE");
                if (detailShown[0]) {
                    contentWrapper.removeAll();
                    contentWrapper.add(tableSp, BorderLayout.CENTER);
                    contentWrapper.revalidate();
                    contentWrapper.repaint();
                    detailShown[0] = false;
                }
                return;
            }
            int modelRow = table.convertRowIndexToModel(viewRow);
            List<HeaderResult> data = repeaterTableModel.getData();
            if (modelRow < 0 || modelRow >= data.size()) return;

            HeaderResult r = data.get(modelRow);

            String reqText = r.rawRequest();
            String respText = headersOnly(r.rawResponse());
            requestArea.setText(reqText != null ? reqText : "(No request data captured)");
            responseArea.setText(respText != null ? respText : "(No response data captured)");
            requestArea.setCaretPosition(0);
            responseArea.setCaretPosition(0);

            if (!detailShown[0]) {
                contentWrapper.removeAll();
                mainSplit.setTopComponent(tableSp);
                mainSplit.setBottomComponent(detailWrapper);
                contentWrapper.add(mainSplit, BorderLayout.CENTER);
                contentWrapper.revalidate();
                contentWrapper.repaint();
                SwingUtilities.invokeLater(() -> mainSplit.setDividerLocation(0.55));
                detailShown[0] = true;
            }
            table.requestFocusInWindow();
        });

        addDetailArrowNav(table, requestArea, responseArea);

        panel.add(bar, BorderLayout.NORTH);
        panel.add(contentWrapper, BorderLayout.CENTER);
        return panel;
    }

    private JTextArea darkTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(new Font("Monospaced", Font.PLAIN, 14));
        area.setBackground(BG_INPUT);
        area.setForeground(TXT);
        area.setCaretColor(ACCENT);
        area.setSelectionColor(TBL_SEL);
        area.setSelectedTextColor(TXT);
        area.setMargin(new Insets(6, 8, 6, 8));
        area.setLineWrap(false);
        return area;
    }

    private void addDetailArrowNav(JTable table, JTextArea requestArea, JTextArea responseArea) {
        KeyAdapter nav = new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_UP || e.getKeyCode() == KeyEvent.VK_DOWN) {
                    int row = table.getSelectedRow();
                    int next = e.getKeyCode() == KeyEvent.VK_UP ? row - 1 : row + 1;
                    if (next >= 0 && next < table.getRowCount()) {
                        table.setRowSelectionInterval(next, next);
                        table.scrollRectToVisible(table.getCellRect(next, 0, true));
                    }
                    e.consume();
                }
            }
        };
        requestArea.addKeyListener(nav);
        responseArea.addKeyListener(nav);
    }

    // ─── Testcase Catalog ─────────────────────────────────────────────────

    private CatalogTableModel catalogModel;

    private JPanel createCatalogPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG);
        panel.setBorder(new EmptyBorder(6, 10, 6, 10));

        catalogModel = new CatalogTableModel(library, selector);

        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        toolbar.setBackground(BG2);
        toolbar.setBorder(new EmptyBorder(4, 8, 4, 8));

        catalogSearchField = darkField(14);
        catalogSearchField.setToolTipText("Search ID, name, or description");
        catalogSearchField.addActionListener(e -> applyCatalogSearch());
        toolbar.add(label("Search")); toolbar.add(catalogSearchField);

        JButton catalogSearchBtn = pill("Filter", ACCENT, ACCENT_H);
        catalogSearchBtn.addActionListener(e -> applyCatalogSearch());
        toolbar.add(catalogSearchBtn);

        JButton catalogClearBtn = pill("Show All", new Color(60, 64, 76), new Color(75, 80, 94));
        catalogClearBtn.addActionListener(e -> {
            catalogSearchField.setText("");
            applyCatalogSearch();
        });
        toolbar.add(catalogClearBtn);

        toolbar.add(Box.createHorizontalStrut(12));

        JButton selectAll = pill("Select All", ACCENT, ACCENT_H);
        selectAll.addActionListener(e -> {
            selector.enableAll();
            catalogModel.fireTableDataChanged();
            statusLabel.setText("All " + library.size() + " testcases enabled");
            statusLabel.setForeground(ACCENT);
        });

        JButton deselectAll = pill("Deselect All", BTN_MUTED, BTN_MUTED_H);
        deselectAll.addActionListener(e -> {
            Set<String> allIds = new HashSet<>();
            for (TestcaseDefinition td : library.getAll()) allIds.add(td.id());
            selector.disableAll(allIds);
            catalogModel.fireTableDataChanged();
            statusLabel.setText("All testcases disabled");
            statusLabel.setForeground(RED_FG);
        });

        JComboBox<String> catFilterCombo = darkCombo(new String[]{"None"});
        Set<String> cats = new TreeSet<>();
        for (TestcaseDefinition td : library.getAll()) {
            if (!td.category().isEmpty()) cats.add(td.category());
        }
        cats.forEach(catFilterCombo::addItem);

        JButton selectCat = pill("Select Category", ACCENT, ACCENT_H);
        selectCat.addActionListener(e -> {
            String cat = (String) catFilterCombo.getSelectedItem();
            if (cat == null || "None".equals(cat)) return;
            for (TestcaseDefinition td : library.getAll()) {
                if (td.category().equals(cat)) selector.setEnabled(td.id(), true);
            }
            catalogModel.fireTableDataChanged();
            statusLabel.setText("Enabled all " + cat + " testcases");
            statusLabel.setForeground(ACCENT);
        });

        JButton deselectCat = pill("Deselect Category", new Color(60, 64, 76), new Color(75, 80, 94));
        deselectCat.addActionListener(e -> {
            String cat = (String) catFilterCombo.getSelectedItem();
            if (cat == null || "None".equals(cat)) return;
            for (TestcaseDefinition td : library.getAll()) {
                if (td.category().equals(cat)) selector.setEnabled(td.id(), false);
            }
            catalogModel.fireTableDataChanged();
            statusLabel.setText("Disabled all " + cat + " testcases");
            statusLabel.setForeground(RED_FG);
        });

        toolbar.add(selectAll);
        toolbar.add(deselectAll);
        toolbar.add(Box.createHorizontalStrut(12));
        toolbar.add(label("Category"));
        toolbar.add(catFilterCombo);
        toolbar.add(selectCat);
        toolbar.add(deselectCat);

        JTable table = new JTable(catalogModel);
        styleTable(table);
        table.getColumnModel().getColumn(0).setMaxWidth(50);
        table.getColumnModel().getColumn(0).setMinWidth(50);
        table.getColumnModel().getColumn(1).setPreferredWidth(120);
        table.getColumnModel().getColumn(2).setPreferredWidth(200);
        table.getColumnModel().getColumn(3).setPreferredWidth(400);
        table.getColumnModel().getColumn(4).setPreferredWidth(100);
        table.getColumnModel().getColumn(5).setPreferredWidth(80);
        for (int i = 1; i <= 4; i++) {
            applyCenterRenderer(table, i);
        }
        DefaultTableCellRenderer catalogModeRenderer = new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean foc, int row, int col) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, val, sel, foc, row, col);
                l.setHorizontalAlignment(SwingConstants.CENTER);
                l.setOpaque(true);
                l.setFont(new Font("SansSerif", Font.BOLD, 12));
                if (sel) { l.setBackground(TBL_SEL); l.setForeground(TXT); }
                else { l.setBackground(new Color(25, 35, 55)); l.setForeground(ACCENT); }
                return l;
            }
        };
        table.getColumnModel().getColumn(5).setCellRenderer(catalogModeRenderer);

        table.getColumnModel().getColumn(0).setCellRenderer(new CheckboxRenderer());
        table.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(new JCheckBox()) {
            {
                JCheckBox cb = (JCheckBox) getComponent();
                cb.setHorizontalAlignment(SwingConstants.CENTER);
                cb.setBackground(BG_ELEV);
            }
        });

        table.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                int row = table.rowAtPoint(e.getPoint());
                int col = table.columnAtPoint(e.getPoint());
                if (row >= 0 && col != 0) {
                    int modelRow = table.convertRowIndexToModel(row);
                    Boolean current = (Boolean) catalogModel.getValueAt(modelRow, 0);
                    catalogModel.setValueAt(!current, modelRow, 0);
                }
            }
        });

        JScrollPane sp = new JScrollPane(table);
        sp.setBorder(BorderFactory.createLineBorder(BORDER));
        sp.getViewport().setBackground(TBL_EVEN);
        sp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        sp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        bottom.setBackground(BG2);
        bottom.setBorder(new EmptyBorder(4, 8, 4, 8));
        JLabel countLabel = new JLabel(library.size() + " testcases in catalog | All enabled");
        countLabel.setFont(new Font("SansSerif", Font.PLAIN, 13));
        countLabel.setForeground(TXT2);
        bottom.add(countLabel);

        catalogModel.addTableModelListener(e -> {
            int disabled = selector.disabledCount();
            int total = library.size();
            int enabled = total - disabled;
            countLabel.setText(total + " testcases in catalog | " + enabled + " enabled, " + disabled + " disabled");
            countLabel.setForeground(disabled > 0 ? WARN_FG : ACCENT);
        });

        panel.add(toolbar, BorderLayout.NORTH);
        panel.add(sp, BorderLayout.CENTER);
        panel.add(bottom, BorderLayout.SOUTH);
        return panel;
    }

    private static class CatalogTableModel extends AbstractTableModel {
        private static final String[] COLS = {"Enabled", "ID", "Name", "Description", "Category", "Mode"};
        private final List<TestcaseDefinition> allTcs;
        private List<TestcaseDefinition> filtered;
        private final TestcaseSelector selector;

        CatalogTableModel(TestcaseLibrary library, TestcaseSelector selector) {
            this.allTcs = library.getAll();
            this.filtered = allTcs;
            this.selector = selector;
        }

        void applyFilter(String search) {
            if (search == null || search.isBlank()) {
                filtered = allTcs;
            } else {
                String lower = search.trim().toLowerCase();
                filtered = allTcs.stream().filter(td ->
                        td.id().toLowerCase().contains(lower)
                        || td.name().toLowerCase().contains(lower)
                        || td.description().toLowerCase().contains(lower)
                        || td.category().toLowerCase().contains(lower)
                ).collect(Collectors.toList());
            }
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return filtered.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int col) { return COLS[col]; }

        @Override public Class<?> getColumnClass(int col) {
            return col == 0 ? Boolean.class : String.class;
        }

        @Override public boolean isCellEditable(int row, int col) {
            return col == 0;
        }

        @Override public Object getValueAt(int row, int col) {
            TestcaseDefinition td = filtered.get(row);
            return switch (col) {
                case 0 -> selector.isEnabled(td.id());
                case 1 -> td.id();
                case 2 -> td.name();
                case 3 -> td.description();
                case 4 -> td.category();
                case 5 -> td.mode() == com.securityheaders.testcase.ExecutionMode.PASSIVE ? "Passive" : "Active";
                default -> "";
            };
        }

        @Override public void setValueAt(Object value, int row, int col) {
            if (col == 0) {
                TestcaseDefinition td = filtered.get(row);
                selector.setEnabled(td.id(), (Boolean) value);
                fireTableCellUpdated(row, col);
            }
        }
    }

    private class CheckboxRenderer extends JCheckBox implements javax.swing.table.TableCellRenderer {
        CheckboxRenderer() {
            setHorizontalAlignment(SwingConstants.CENTER);
            setOpaque(true);
        }

        @Override public Component getTableCellRendererComponent(JTable table, Object value,
                boolean sel, boolean foc, int row, int col) {
            setSelected(value instanceof Boolean b && b);
            setBackground(sel ? TBL_SEL : (row % 2 == 0 ? TBL_EVEN : TBL_ODD));
            setForeground(ACCENT);
            return this;
        }
    }

    private JPanel createScopeExportPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 12));
        panel.setBackground(BG);
        panel.setBorder(new EmptyBorder(10, 14, 10, 14));

        // --- Scope section (Burp-style table with Add/Edit/Remove) ---
        JPanel scopeRow = new JPanel(new GridLayout(1, 2, 14, 0));
        scopeRow.setOpaque(false);

        scopeRow.add(buildScopeTable("Include in scope", ACCENT, true));
        scopeRow.add(buildScopeTable("Exclude from scope", RED_FG, false));

        scopeRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 250));
        scopeRow.setPreferredSize(new Dimension(0, 250));

        JPanel scopeSection = new JPanel(new BorderLayout(0, 8));
        scopeSection.setOpaque(false);
        scopeSection.add(sectionLabel("SCOPE CONFIGURATION"), BorderLayout.NORTH);
        scopeSection.add(scopeRow, BorderLayout.CENTER);

        // --- Export section ---
        JPanel exportSection = new JPanel(new BorderLayout(0, 8));
        exportSection.setOpaque(false);
        exportSection.add(sectionLabel("EXPORT"), BorderLayout.NORTH);

        JPanel exportBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        exportBtns.setOpaque(false);

        JButton expFiltered = pill("Filtered Raw Results CSV", ACCENT, ACCENT_H);
        expFiltered.addActionListener(e -> exportFilteredRaw());
        JButton expAll = pill("Raw Results CSV", BTN_MUTED, BTN_MUTED_H);
        expAll.addActionListener(e -> exportAllRaw());
        JButton expTc = pill("Testcase Results CSV", BTN_MUTED, BTN_MUTED_H);
        expTc.addActionListener(e -> exportTestcaseResults());

        exportBtns.add(expFiltered);
        exportBtns.add(expAll);
        exportBtns.add(expTc);
        exportSection.add(exportBtns, BorderLayout.CENTER);

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setOpaque(false);
        scopeSection.setAlignmentX(Component.LEFT_ALIGNMENT);
        exportSection.setAlignmentX(Component.LEFT_ALIGNMENT);
        content.add(scopeSection);
        content.add(Box.createVerticalStrut(14));
        content.add(exportSection);
        content.add(Box.createVerticalGlue());

        panel.add(content, BorderLayout.NORTH);
        return panel;
    }

    private JPanel buildScopeTable(String title, Color accent, boolean isAllowlist) {
        JPanel card = new JPanel(new BorderLayout(0, 6));
        card.setBackground(BG_ELEV);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_S),
                new EmptyBorder(10, 12, 10, 12)));

        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        titleLabel.setForeground(accent);

        JLabel hint = new JLabel(isAllowlist
                ? "If empty, all hosts are in scope. Supports wildcards: *.example.com"
                : "Blocklist takes precedence over allowlist. Supports wildcards: *.example.com");
        hint.setFont(new Font("SansSerif", Font.PLAIN, 12));
        hint.setForeground(TXT_M);

        JPanel headerPanel = new JPanel();
        headerPanel.setOpaque(false);
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        headerPanel.add(titleLabel);
        headerPanel.add(Box.createVerticalStrut(2));
        headerPanel.add(hint);

        // Table model: Enabled | Host pattern
        javax.swing.table.DefaultTableModel model = new javax.swing.table.DefaultTableModel(
                new Object[]{"Enabled", "Host Pattern"}, 0) {
            @Override public Class<?> getColumnClass(int col) {
                return col == 0 ? Boolean.class : String.class;
            }
            @Override public boolean isCellEditable(int row, int col) { return true; }
        };

        JTable table = new JTable(model);
        styleTable(table);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.getColumnModel().getColumn(0).setMinWidth(65);
        table.getColumnModel().getColumn(0).setMaxWidth(65);
        table.getColumnModel().getColumn(0).setPreferredWidth(65);
        table.getColumnModel().getColumn(1).setHeaderRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean foc, int row, int col) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, val, sel, foc, row, col);
                l.setBackground(TBL_HDR); l.setForeground(TXT2);
                l.setFont(new Font("SansSerif", Font.BOLD, 12));
                l.setHorizontalAlignment(SwingConstants.LEFT);
                l.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER),
                        new EmptyBorder(6, 16, 6, 8)));
                l.setOpaque(true);
                return l;
            }
        });
        table.getColumnModel().getColumn(1).setCellRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean foc, int row, int col) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, val, sel, foc, row, col);
                l.setBorder(new EmptyBorder(0, 16, 0, 8));
                return l;
            }
        });

        JScrollPane sp = new JScrollPane(table);
        sp.setBorder(BorderFactory.createLineBorder(BORDER_S));
        sp.getViewport().setBackground(TBL_EVEN);
        sp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        sp.setPreferredSize(new Dimension(300, 160));

        // Buttons
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        btnPanel.setOpaque(false);

        JButton addBtn = pill("Add", ACCENT, ACCENT_H);
        addBtn.addActionListener(e -> {
            String pattern = JOptionPane.showInputDialog(SecurityHeadersTab.this,
                    "Enter host pattern (e.g. example.com or *.example.com):",
                    "Add " + title, JOptionPane.PLAIN_MESSAGE);
            if (pattern != null && !pattern.trim().isEmpty()) {
                model.addRow(new Object[]{Boolean.TRUE, pattern.trim().toLowerCase()});
                syncScopeFromTable(model, isAllowlist);
            }
        });

        JButton editBtn = pill("Edit", BTN_MUTED, BTN_MUTED_H);
        editBtn.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row < 0) return;
            String current = (String) model.getValueAt(row, 1);
            String pattern = JOptionPane.showInputDialog(SecurityHeadersTab.this,
                    "Edit host pattern:", current);
            if (pattern != null && !pattern.trim().isEmpty()) {
                model.setValueAt(pattern.trim().toLowerCase(), row, 1);
                syncScopeFromTable(model, isAllowlist);
            }
        });

        JButton removeBtn = pill("Remove", new Color(70, 40, 44), new Color(90, 50, 55));
        removeBtn.setForeground(RED_FG);
        removeBtn.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row >= 0) {
                model.removeRow(row);
                syncScopeFromTable(model, isAllowlist);
            }
        });

        JButton pasteBtn = pill("Paste", BTN_MUTED, BTN_MUTED_H);
        pasteBtn.setToolTipText("Paste hosts from clipboard (one per line)");
        pasteBtn.addActionListener(e -> {
            try {
                String clip = (String) Toolkit.getDefaultToolkit()
                        .getSystemClipboard().getData(java.awt.datatransfer.DataFlavor.stringFlavor);
                if (clip != null) {
                    for (String line : clip.split("\\R")) {
                        String trimmed = line.trim().toLowerCase();
                        if (!trimmed.isEmpty()) {
                            model.addRow(new Object[]{Boolean.TRUE, trimmed});
                        }
                    }
                    syncScopeFromTable(model, isAllowlist);
                }
            } catch (Exception ignored) {}
        });

        btnPanel.add(addBtn);
        btnPanel.add(editBtn);
        btnPanel.add(removeBtn);
        btnPanel.add(pasteBtn);

        // Sync on cell edits (enable/disable toggle, inline host edit)
        model.addTableModelListener(e -> syncScopeFromTable(model, isAllowlist));

        card.add(headerPanel, BorderLayout.NORTH);
        card.add(sp, BorderLayout.CENTER);
        card.add(btnPanel, BorderLayout.SOUTH);
        return card;
    }

    private void syncScopeFromTable(javax.swing.table.DefaultTableModel model, boolean isAllowlist) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < model.getRowCount(); i++) {
            Boolean enabled = (Boolean) model.getValueAt(i, 0);
            String pattern = (String) model.getValueAt(i, 1);
            if (Boolean.TRUE.equals(enabled) && pattern != null && !pattern.isBlank()) {
                sb.append(pattern.trim()).append("\n");
            }
        }
        if (isAllowlist) {
            scopeManager.updateAllowlist(sb.toString());
        } else {
            scopeManager.updateBlocklist(sb.toString());
        }
        statusLabel.setText("Scope updated");
        statusLabel.setForeground(ACCENT);
    }

    // ─── Workbook import ────────────────────────────────────────────────────

    private void importWorkbook() {
        JFileChooser fc = new JFileChooser();
        fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Excel Workbooks", "xlsx", "xls"));
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

        File file = fc.getSelectedFile();
        new SwingWorker<Void, Void>() {
            int imported = 0;
            @Override protected Void doInBackground() throws Exception {
                WorkbookImporter importer = new WorkbookImporter();
                List<TestcaseDefinition> tcs = importer.importTestcases(file);
                for (TestcaseDefinition tc : tcs) {
                    library.addOrReplace(tc);
                }
                importer.importBaseline(file);
                imported = tcs.size();
                return null;
            }
            @Override protected void done() {
                try {
                    get();
                    statusLabel.setText("Imported " + imported + " testcases from workbook");
                    statusLabel.setForeground(ACCENT);
                } catch (Exception ex) {
                    statusLabel.setText("Import failed: " + ex.getCause().getMessage());
                    statusLabel.setForeground(RED_FG);
                }
            }
        }.execute();
    }

    // ─── Refresh / Filter ────────────────────────────────────────────────────

    public void refreshViews() {
        refreshingCombos = true;
        try {
            List<HeaderResult> all = resultStore.getAll();

            // Update Raw Results filter combos
            Set<String> hosts = all.stream().map(HeaderResult::host).collect(Collectors.toCollection(TreeSet::new));
            String selectedHost = (String) rawHostCombo.getSelectedItem();
            rawHostCombo.removeAllItems();
            rawHostCombo.addItem("None");
            hosts.forEach(rawHostCombo::addItem);
            if (selectedHost != null && hosts.contains(selectedHost)) {
                rawHostCombo.setSelectedItem(selectedHost);
            }

            Set<Integer> statuses = all.stream().map(HeaderResult::statusCode).collect(Collectors.toCollection(TreeSet::new));
            String selectedStatus = (String) rawStatusCombo.getSelectedItem();
            rawStatusCombo.removeAllItems();
            rawStatusCombo.addItem("None");
            statuses.forEach(s -> rawStatusCombo.addItem(String.valueOf(s)));
            if (selectedStatus != null) {
                for (int i = 0; i < rawStatusCombo.getItemCount(); i++) {
                    if (rawStatusCombo.getItemAt(i).equals(selectedStatus)) {
                        rawStatusCombo.setSelectedIndex(i);
                        break;
                    }
                }
            }

            // Update Endpoint Summary host combo
            Set<String> epHosts = all.stream().map(HeaderResult::host).collect(Collectors.toCollection(TreeSet::new));
            String selectedEpHost = (String) epHostCombo.getSelectedItem();
            epHostCombo.removeAllItems();
            epHostCombo.addItem("None");
            epHosts.forEach(epHostCombo::addItem);
            if (selectedEpHost != null && epHosts.contains(selectedEpHost)) {
                epHostCombo.setSelectedItem(selectedEpHost);
            }
        } finally {
            refreshingCombos = false;
        }

        applyRawFilters();
        applyHostFilters();
        applyEpFilters();
        refreshDashboard();
    }

    public void refreshRepeaterViews() {
        refreshingCombos = true;
        try {
            List<HeaderResult> all = repeaterResultStore.getAll();

            Set<String> hosts = all.stream().map(HeaderResult::host).collect(Collectors.toCollection(TreeSet::new));
            String selectedHost = (String) repHostCombo.getSelectedItem();
            repHostCombo.removeAllItems();
            repHostCombo.addItem("None");
            hosts.forEach(repHostCombo::addItem);
            if (selectedHost != null && hosts.contains(selectedHost)) {
                repHostCombo.setSelectedItem(selectedHost);
            }

            Set<Integer> statuses = all.stream().map(HeaderResult::statusCode).collect(Collectors.toCollection(TreeSet::new));
            String selectedStatus = (String) repStatusCombo.getSelectedItem();
            repStatusCombo.removeAllItems();
            repStatusCombo.addItem("None");
            statuses.forEach(s -> repStatusCombo.addItem(String.valueOf(s)));
            if (selectedStatus != null) {
                for (int i = 0; i < repStatusCombo.getItemCount(); i++) {
                    if (repStatusCombo.getItemAt(i).equals(selectedStatus)) {
                        repStatusCombo.setSelectedIndex(i);
                        break;
                    }
                }
            }
        } finally {
            refreshingCombos = false;
        }

        applyRepeaterFilters();
    }

    public void refreshTestcaseViews() {
        refreshingCombos = true;
        try {
            List<TestcaseResult> all = tcResultStore.getAll();

            Set<String> hosts = new TreeSet<>();
            Set<String> categories = new TreeSet<>();
            for (TestcaseResult r : all) {
                if (r.host() != null && !r.host().isEmpty()) hosts.add(r.host());
                String tcId = r.testcaseId();
                TestcaseDefinition def = library.get(tcId);
                if (def != null && !def.category().isEmpty()) categories.add(def.category());
            }
            String selHost = (String) tcHostCombo.getSelectedItem();
            tcHostCombo.removeAllItems();
            tcHostCombo.addItem("None");
            hosts.forEach(tcHostCombo::addItem);
            if (selHost != null && hosts.contains(selHost)) tcHostCombo.setSelectedItem(selHost);

            String selCat = (String) tcCategoryCombo.getSelectedItem();
            tcCategoryCombo.removeAllItems();
            tcCategoryCombo.addItem("None");
            categories.forEach(tcCategoryCombo::addItem);
            if (selCat != null && categories.contains(selCat)) tcCategoryCombo.setSelectedItem(selCat);
        } finally {
            refreshingCombos = false;
        }

        applyTcFilters();
        refreshDashboard();
    }

    private void applyRawFilters() {
        List<HeaderResult> all = resultStore.getAll();
        FilterState fs = buildRawFilterState();
        currentFiltered = filterService.apply(all, fs);
        rawTableModel.setData(currentFiltered);
        rawFilterIndicator.setText(fs.isActive() ? "Filtered" : "");
    }

    private void applyRepeaterFilters() {
        List<HeaderResult> all = repeaterResultStore.getAll();
        FilterState fs = buildRepeaterFilterState();
        currentRepFiltered = filterService.apply(all, fs);
        repeaterTableModel.setData(currentRepFiltered);
        repFilterIndicator.setText(fs.isActive() ? "Filtered" : "");
    }

    private void applyTcFilters() {
        List<TestcaseResult> all = tcResultStore.getAll();

        String pathFilter = tcPathField.getText().trim().toLowerCase();
        String hostFilter = tcHostCombo.getSelectedIndex() <= 0 ? null : (String) tcHostCombo.getSelectedItem();
        String modeFilter = (String) tcModeCombo.getSelectedItem();
        String statusFilter = (String) tcStatusCombo.getSelectedItem();
        String catFilter = (String) tcCategoryCombo.getSelectedItem();

        currentTcFiltered = all.stream().filter(r -> {
            if (!pathFilter.isEmpty()) {
                String pq = r.pathAndQuery();
                if (pq == null || !pq.toLowerCase().contains(pathFilter)) return false;
            }
            if (hostFilter != null && !hostFilter.equalsIgnoreCase(r.host())) return false;
            if (modeFilter != null && !"None".equals(modeFilter)) {
                if (!r.mode().name().equals(modeFilter)) return false;
            }
            if (statusFilter != null && !"None".equals(statusFilter)) {
                if (!r.status().name().equals(statusFilter)) return false;
            }
            if (catFilter != null && !"None".equals(catFilter)) {
                TestcaseDefinition def = library.get(r.testcaseId());
                if (def == null || !def.category().equals(catFilter)) return false;
            }
            return true;
        }).collect(Collectors.toList());

        tcTableModel.setData(currentTcFiltered);

        long total = all.size();
        long pass = all.stream().filter(r -> r.status() == ResultStatus.PASS).count();
        long fail = all.stream().filter(r -> r.status() == ResultStatus.FAIL).count();
        long errors = all.stream().filter(r -> r.status() == ResultStatus.ERROR
                || r.status() == ResultStatus.INCONCLUSIVE).count();

    }

    private void clearRawFilters() {
        rawSearchField.setText("");
        rawHostCombo.setSelectedIndex(0);
        rawStatusCombo.setSelectedIndex(0);
        rawHeaderCombo.setSelectedIndex(0);
        applyRawFilters();
    }

    private void clearRepeaterFilters() {
        repSearchField.setText("");
        repHostCombo.setSelectedIndex(0);
        repStatusCombo.setSelectedIndex(0);
        repHeaderCombo.setSelectedIndex(0);
        applyRepeaterFilters();
    }

    private void applyHostFilters() {
        List<HostSummary> all = summaryService.computeHostSummaries(resultStore.getAll());
        String search = hostSearchField.getText().trim().toLowerCase();
        int headerIdx = hostHeaderCombo.getSelectedIndex();

        List<HostSummary> filtered = all.stream().filter(h -> {
            if (!search.isEmpty() && !h.host().toLowerCase().contains(search)) return false;
            return switch (headerIdx) {
                case 1 -> h.hstsMissing() > 0 && h.cacheControlMissing() > 0
                        && h.xfoMissing() > 0 && h.xctoMissing() > 0
                        && h.acaoMissing() > 0 && h.cspMissing() > 0;
                case 2 -> h.hstsMissing() > 0;
                case 3 -> h.cacheControlMissing() > 0;
                case 4 -> h.xfoMissing() > 0;
                case 5 -> h.xctoMissing() > 0;
                case 6 -> h.acaoMissing() > 0;
                case 7 -> h.cspMissing() > 0;
                default -> true;
            };
        }).collect(Collectors.toList());

        hostTableModel.setData(filtered);
        boolean active = !search.isEmpty() || headerIdx > 0;
        hostFilterIndicator.setText(active ? "Filtered" : "");
    }

    private void applyEpFilters() {
        List<EndpointSummary> all = summaryService.computeEndpointSummaries(resultStore.getAll());
        String search = epSearchField.getText().trim().toLowerCase();
        String hostFilter = epHostCombo.getSelectedIndex() <= 0 ? null : (String) epHostCombo.getSelectedItem();
        int headerIdx = epHeaderCombo.getSelectedIndex();

        List<EndpointSummary> filtered = all.stream().filter(ep -> {
            if (!search.isEmpty()
                    && !ep.host().toLowerCase().contains(search)
                    && !ep.pathAndQuery().toLowerCase().contains(search)) return false;
            if (hostFilter != null && !ep.host().equalsIgnoreCase(hostFilter)) return false;
            return switch (headerIdx) {
                case 1 -> ep.responsesWithMissing() > 0;
                case 2 -> ep.hstsMissing() > 0 && ep.cacheControlMissing() > 0
                        && ep.xfoMissing() > 0 && ep.xctoMissing() > 0
                        && ep.acaoMissing() > 0 && ep.cspMissing() > 0;
                case 3 -> ep.hstsMissing() > 0;
                case 4 -> ep.cacheControlMissing() > 0;
                case 5 -> ep.xfoMissing() > 0;
                case 6 -> ep.xctoMissing() > 0;
                case 7 -> ep.acaoMissing() > 0;
                case 8 -> ep.cspMissing() > 0;
                default -> true;
            };
        }).collect(Collectors.toList());

        epTableModel.setTestcaseCounts(tcResultStore.getAll(), library.size(), library);
        epTableModel.setData(filtered);
        boolean active = !search.isEmpty() || hostFilter != null || headerIdx > 0;
        epFilterIndicator.setText(active ? "Filtered" : "");
    }

    private void applyCatalogSearch() {
        catalogModel.applyFilter(catalogSearchField.getText());
    }

    private FilterState buildRawFilterState() {
        return buildFilterState(rawSearchField, rawHostCombo, rawStatusCombo, rawHeaderCombo);
    }

    private FilterState buildRepeaterFilterState() {
        return buildFilterState(repSearchField, repHostCombo, repStatusCombo, repHeaderCombo);
    }

    private FilterState buildFilterState(JTextField searchField, JComboBox<String> hostCombo,
                                          JComboBox<String> statusCombo, JComboBox<String> headerCombo) {
        String search = searchField.getText();
        String host = hostCombo.getSelectedIndex() <= 0 ? null : (String) hostCombo.getSelectedItem();
        Set<Integer> statuses = Collections.emptySet();
        if (statusCombo.getSelectedIndex() > 0) {
            try {
                statuses = Set.of(Integer.parseInt((String) statusCombo.getSelectedItem()));
            } catch (NumberFormatException ignored) {}
        }
        FilterState.HeaderFilter hf = switch (headerCombo.getSelectedIndex()) {
            case 1 -> FilterState.HeaderFilter.ANY_MISSING;
            case 2 -> FilterState.HeaderFilter.ALL_MISSING;
            case 3 -> FilterState.HeaderFilter.HSTS_MISSING;
            case 4 -> FilterState.HeaderFilter.CACHE_CONTROL_MISSING;
            case 5 -> FilterState.HeaderFilter.XFO_MISSING;
            case 6 -> FilterState.HeaderFilter.XCTO_MISSING;
            case 7 -> FilterState.HeaderFilter.ACAO_MISSING;
            case 8 -> FilterState.HeaderFilter.CSP_MISSING;
            default -> FilterState.HeaderFilter.ALL;
        };
        return new FilterState(search, host, statuses, hf);
    }

    // ─── Export ──────────────────────────────────────────────────────────────

    private void exportFilteredRaw() {
        File f = chooseSave("filtered_raw_results.csv", "CSV Files", "csv");
        if (f == null) return;
        runExport(() -> csvExport.exportRawResults(f, currentFiltered), f);
    }

    private void exportAllRaw() {
        File f = chooseSave("all_raw_results.csv", "CSV Files", "csv");
        if (f == null) return;
        runExport(() -> csvExport.exportRawResults(f, resultStore.getAll()), f);
    }

    private void exportTestcaseResults() {
        File f = chooseSave("testcase_results.csv", "CSV Files", "csv");
        if (f == null) return;
        runExport(() -> csvExport.exportTestcaseResults(f, tcResultStore.getAll()), f);
    }

    private void exportAllZip() {
        File f = chooseSave("security_headers_export.zip", "ZIP Files", "zip");
        if (f == null) return;
        List<HeaderResult> all = resultStore.getAll();
        List<HostSummary> hs = summaryService.computeHostSummaries(all);
        List<EndpointSummary> es = summaryService.computeEndpointSummaries(all);
        List<TestcaseResult> tcs = tcResultStore.getAll();
        runExport(() -> csvExport.exportAllZipWithTestcases(f, all, hs, es, tcs), f);
    }

    private void runExport(ExportTask task, File f) {
        new SwingWorker<Void, Void>() {
            @Override protected Void doInBackground() throws Exception {
                task.run(); return null;
            }
            @Override protected void done() {
                try {
                    get();
                    statusLabel.setText("Exported: " + f.getName());
                    statusLabel.setForeground(ACCENT);
                } catch (Exception ex) {
                    statusLabel.setText("Export failed: " + ex.getCause().getMessage());
                    statusLabel.setForeground(RED_FG);
                    JOptionPane.showMessageDialog(SecurityHeadersTab.this,
                            "Export failed:\n" + ex.getCause().getMessage(),
                            "Export Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }.execute();
    }

    @FunctionalInterface
    private interface ExportTask { void run() throws Exception; }

    private File chooseSave(String defaultName, String desc, String ext) {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File(defaultName));
        fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(desc, ext));
        if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File f = fc.getSelectedFile();
            if (!f.getName().endsWith("." + ext)) {
                f = new File(f.getAbsolutePath() + "." + ext);
            }
            return f;
        }
        return null;
    }

    private static String headersOnly(String raw) {
        if (raw == null) return null;
        int sep = raw.indexOf("\r\n\r\n");
        if (sep >= 0) return raw.substring(0, sep);
        sep = raw.indexOf("\n\n");
        if (sep >= 0) return raw.substring(0, sep);
        return raw;
    }

    // ─── Table styling ───────────────────────────────────────────────────────

    private void styleTable(JTable table) {
        table.setRowHeight(30);
        table.setShowHorizontalLines(true);
        table.setShowVerticalLines(false);
        table.setGridColor(TBL_DIV);
        table.setBackground(TBL_EVEN);
        table.setForeground(TXT);
        table.setSelectionBackground(TBL_SEL);
        table.setSelectionForeground(TXT);
        table.setFont(new Font("SansSerif", Font.PLAIN, 14));
        table.setFillsViewportHeight(true);
        table.setIntercellSpacing(new Dimension(0, 1));
        table.setAutoCreateRowSorter(true);

        JTableHeader hdr = table.getTableHeader();
        hdr.setDefaultRenderer(new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean foc, int row, int col) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, val, sel, foc, row, col);
                l.setBackground(TBL_HDR); l.setForeground(TXT2);
                l.setFont(new Font("SansSerif", Font.BOLD, 12));
                l.setHorizontalAlignment(SwingConstants.CENTER);
                l.setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER),
                        new EmptyBorder(6, 8, 6, 8)));
                l.setOpaque(true);
                return l;
            }
        });
        hdr.setPreferredSize(new Dimension(0, 34));
        hdr.setReorderingAllowed(false);

        DefaultTableCellRenderer baseRend = new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean foc, int row, int col) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, val, sel, foc, row, col);
                if (!sel) {
                    l.setBackground(row % 2 == 0 ? TBL_EVEN : TBL_ODD);
                    l.setForeground(TXT);
                }
                l.setBorder(new EmptyBorder(0, 8, 0, 8));
                return l;
            }
        };
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(baseRend);
        }
    }

    private void applyPresenceRenderer(JTable table, int from, int to) {
        DefaultTableCellRenderer r = new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean foc, int row, int col) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, val, sel, foc, row, col);
                l.setHorizontalAlignment(SwingConstants.CENTER);
                l.setOpaque(true);
                l.setFont(new Font("SansSerif", Font.BOLD, 12));
                l.setBorder(new EmptyBorder(4, 4, 4, 4));
                if (!sel && val instanceof String txt) {
                    if ("PRESENT".equals(txt)) { l.setBackground(GREEN_BG); l.setForeground(GREEN_FG); }
                    else if ("MISSING".equals(txt)) { l.setBackground(RED_BG); l.setForeground(RED_FG); }
                    else if ("COVERED".equals(txt)) { l.setBackground(WARN_BG); l.setForeground(WARN_FG); }
                    else { l.setBackground(row % 2 == 0 ? TBL_EVEN : TBL_ODD); l.setForeground(TXT); }
                } else if (sel) { l.setBackground(TBL_SEL); l.setForeground(TXT); }
                return l;
            }
        };
        for (int i = from; i <= to; i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(r);
        }
    }

    private void applyAcaoPresenceRenderer(JTable table, int col) {
        DefaultTableCellRenderer r = new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean foc, int row, int column) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, val, sel, foc, row, column);
                l.setHorizontalAlignment(SwingConstants.CENTER);
                l.setOpaque(true);
                l.setFont(new Font("SansSerif", Font.BOLD, 12));
                l.setBorder(new EmptyBorder(4, 4, 4, 4));
                if (!sel && val instanceof String txt) {
                    if ("PRESENT".equals(txt)) { l.setBackground(GREEN_BG); l.setForeground(GREEN_FG); }
                    else if ("MISSING".equals(txt)) { l.setBackground(ORANGE_BG); l.setForeground(ORANGE_FG); }
                    else if ("COVERED".equals(txt)) { l.setBackground(WARN_BG); l.setForeground(WARN_FG); }
                    else { l.setBackground(row % 2 == 0 ? TBL_EVEN : TBL_ODD); l.setForeground(TXT); }
                } else if (sel) { l.setBackground(TBL_SEL); l.setForeground(TXT); }
                return l;
            }
        };
        table.getColumnModel().getColumn(col).setCellRenderer(r);
    }

    private void applyCountRenderer(JTable table, int from, int to) {
        DefaultTableCellRenderer r = new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean foc, int row, int col) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, val, sel, foc, row, col);
                l.setHorizontalAlignment(SwingConstants.CENTER);
                l.setOpaque(true);
                l.setFont(new Font("SansSerif", Font.BOLD, 13));
                l.setBorder(new EmptyBorder(4, 4, 4, 4));
                if (!sel && val instanceof Integer n) {
                    l.setBackground(n > 0 ? RED_BG : GREEN_BG);
                    l.setForeground(n > 0 ? RED_FG : GREEN_FG);
                } else if (sel) { l.setBackground(TBL_SEL); l.setForeground(TXT); }
                return l;
            }
        };
        for (int i = from; i <= to; i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(r);
        }
    }

    private void applyTestcaseHeaderRenderer(JTable table, int from, int to) {
        DefaultTableCellRenderer r = new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean foc, int row, int column) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, val, sel, foc, row, column);
                l.setHorizontalAlignment(SwingConstants.CENTER);
                l.setOpaque(true);
                l.setFont(new Font("SansSerif", Font.BOLD, 12));
                l.setBorder(new EmptyBorder(4, 4, 4, 4));
                if (!sel && val instanceof String s) {
                    switch (s) {
                        case "PASS", "PRESENT" -> { l.setBackground(GREEN_BG); l.setForeground(GREEN_FG); }
                        case "FAIL", "MISSING" -> { l.setBackground(RED_BG); l.setForeground(RED_FG); }
                        case "COVERED", "ERROR", "INCONCLUSIVE" -> { l.setBackground(WARN_BG); l.setForeground(WARN_FG); }
                        default -> { l.setBackground(row % 2 == 0 ? TBL_EVEN : TBL_ODD); l.setForeground(TXT_M); }
                    }
                } else if (sel) { l.setBackground(TBL_SEL); l.setForeground(TXT); }
                return l;
            }
        };
        for (int i = from; i <= to; i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(r);
        }
    }

    private void applyCenterRenderer(JTable table, int col) {
        DefaultTableCellRenderer r = new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean foc, int row, int column) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, val, sel, foc, row, column);
                l.setHorizontalAlignment(SwingConstants.CENTER);
                l.setOpaque(true);
                l.setBackground(sel ? TBL_SEL : (row % 2 == 0 ? TBL_EVEN : TBL_ODD));
                l.setForeground(TXT);
                return l;
            }
        };
        table.getColumnModel().getColumn(col).setCellRenderer(r);
    }

    private void applyAcaoChecksRenderer(JTable table, int col) {
        DefaultTableCellRenderer r = new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean foc, int row, int column) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, val, sel, foc, row, column);
                l.setHorizontalAlignment(SwingConstants.CENTER);
                l.setOpaque(true);
                l.setFont(new Font("SansSerif", Font.BOLD, 12));
                l.setBorder(new EmptyBorder(4, 4, 4, 4));
                if (!sel && val instanceof String s) {
                    switch (s) {
                        case "FAIL" -> { l.setBackground(RED_BG); l.setForeground(RED_FG); }
                        case "PASS" -> { l.setBackground(GREEN_BG); l.setForeground(GREEN_FG); }
                        default -> { l.setBackground(row % 2 == 0 ? TBL_EVEN : TBL_ODD); l.setForeground(TXT_M); }
                    }
                } else if (sel) { l.setBackground(TBL_SEL); l.setForeground(TXT); }
                return l;
            }
        };
        table.getColumnModel().getColumn(col).setCellRenderer(r);
    }

    private void applyTcAcaoChecksRenderer(JTable table, int col) {
        DefaultTableCellRenderer r = new DefaultTableCellRenderer() {
            @Override public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean foc, int row, int column) {
                JLabel l = (JLabel) super.getTableCellRendererComponent(t, val, sel, foc, row, column);
                l.setHorizontalAlignment(SwingConstants.CENTER);
                l.setOpaque(true);
                l.setFont(new Font("SansSerif", Font.BOLD, 12));
                l.setBorder(new EmptyBorder(4, 4, 4, 4));
                if (!sel && val instanceof String s) {
                    switch (s) {
                        case "FAIL" -> { l.setBackground(RED_BG); l.setForeground(RED_FG); }
                        case "PASS" -> { l.setBackground(GREEN_BG); l.setForeground(GREEN_FG); }
                        default -> { l.setBackground(row % 2 == 0 ? TBL_EVEN : TBL_ODD); l.setForeground(TXT_M); }
                    }
                } else if (sel) { l.setBackground(TBL_SEL); l.setForeground(TXT); }
                return l;
            }
        };
        table.getColumnModel().getColumn(col).setCellRenderer(r);
    }

    // ─── Scope cards ─────────────────────────────────────────────────────────


    // ─── Status bar ──────────────────────────────────────────────────────────

    private JPanel createStatusBar() {
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBackground(BG2);
        bar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER),
                new EmptyBorder(5, 14, 5, 14)));
        statusLabel = new JLabel("Monitoring");
        statusLabel.setFont(new Font("SansSerif", Font.PLAIN, 12));
        statusLabel.setForeground(ACCENT);
        bar.add(statusLabel, BorderLayout.WEST);
        return bar;
    }

    // ─── Widget helpers ──────────────────────────────────────────────────────

    private JLabel label(String text) {
        JLabel l = new JLabel(text);
        l.setFont(new Font("SansSerif", Font.PLAIN, 12));
        l.setForeground(TXT_M);
        return l;
    }

    private static Icon createIcon(int size, Color color, String type) {
        return new Icon() {
            @Override public int getIconWidth() { return size; }
            @Override public int getIconHeight() { return size; }
            @Override public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.translate(x, y);
                g2.setColor(color);
                switch (type) {
                    case "shield" -> {
                        int[] px = {size / 2, size - 1, size - 1, size / 2, 0, 0};
                        int[] py = {0, size / 5, size * 3 / 5, size - 1, size * 3 / 5, size / 5};
                        g2.fillPolygon(px, py, px.length);
                    }
                    case "grid" -> {
                        int gap = 2, cell = (size - gap * 2) / 3;
                        for (int r = 0; r < 3; r++)
                            for (int col = 0; col < 3; col++)
                                g2.fillRoundRect(col * (cell + gap), r * (cell + gap), cell, cell, 2, 2);
                    }
                    case "globe" -> {
                        g2.setStroke(new BasicStroke(1.5f));
                        g2.drawOval(1, 1, size - 3, size - 3);
                        g2.drawLine(size / 2, 1, size / 2, size - 2);
                        g2.drawLine(1, size / 2, size - 2, size / 2);
                        g2.drawOval(size / 4, 1, size / 2, size - 3);
                    }
                    case "endpoint" -> {
                        g2.setStroke(new BasicStroke(1.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                        g2.drawLine(3, size / 2, size - 4, size / 2);
                        g2.fillOval(0, size / 2 - 3, 6, 6);
                        g2.fillOval(size - 7, size / 2 - 3, 6, 6);
                    }
                    case "check" -> {
                        g2.setStroke(new BasicStroke(2.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                        g2.drawLine(2, size / 2, size / 3 + 1, size - 3);
                        g2.drawLine(size / 3 + 1, size - 3, size - 2, 3);
                    }
                    case "repeat" -> {
                        g2.setStroke(new BasicStroke(1.8f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                        g2.drawArc(2, 2, size - 5, size - 5, 30, 300);
                        g2.fillPolygon(new int[]{size - 3, size - 7, size - 3}, new int[]{1, 4, 7}, 3);
                    }
                    case "list" -> {
                        int gap = (size - 2) / 4;
                        for (int i = 0; i < 4; i++) {
                            int ly = 2 + i * gap;
                            g2.fillOval(0, ly, 3, 3);
                            g2.fillRoundRect(6, ly, size - 7, 2, 1, 1);
                        }
                    }
                    case "dash" -> {
                        int half = size / 2;
                        g2.fillRoundRect(0, 0, half - 2, half - 2, 3, 3);
                        g2.fillRoundRect(half, 0, half - 1, half - 2, 3, 3);
                        g2.fillRoundRect(0, half, half - 2, half - 1, 3, 3);
                        g2.fillRoundRect(half, half, half - 1, half - 1, 3, 3);
                    }
                    case "gear" -> {
                        g2.setStroke(new BasicStroke(1.5f));
                        int cx = size / 2, cy = size / 2, r = size / 2 - 3;
                        g2.drawOval(cx - r, cy - r, r * 2, r * 2);
                        g2.fillOval(cx - 2, cy - 2, 4, 4);
                        for (int angle = 0; angle < 360; angle += 45) {
                            double rad = Math.toRadians(angle);
                            int tx = (int) (cx + (r + 2) * Math.cos(rad));
                            int ty = (int) (cy - (r + 2) * Math.sin(rad));
                            g2.fillRect(tx - 1, ty - 1, 3, 3);
                        }
                    }
                }
                g2.dispose();
            }
        };
    }

    private JLabel sectionLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(new Font("SansSerif", Font.BOLD, 13));
        l.setForeground(TXT_M);
        l.setBorder(new EmptyBorder(0, 2, 6, 0));
        return l;
    }

    private JTextField darkField(int cols) {
        JTextField f = new JTextField(cols);
        f.setBackground(BG_INPUT); f.setForeground(TXT);
        f.setCaretColor(ACCENT);
        f.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_S),
                new EmptyBorder(4, 8, 4, 8)));
        f.setFont(new Font("SansSerif", Font.PLAIN, 14));
        return f;
    }

    private JComboBox<String> darkCombo(String[] items) {
        JComboBox<String> c = new JComboBox<>(items);
        c.setBackground(BG_INPUT); c.setForeground(TXT);
        c.setFont(new Font("SansSerif", Font.PLAIN, 13));
        c.setBorder(BorderFactory.createLineBorder(BORDER_S));
        return c;
    }

    private JButton pill(String text, Color bg, Color hover) {
        JButton b = new JButton(text) {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(getBackground());
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 4, 4);
                g2.dispose();
                super.paintComponent(g);
            }
        };
        b.setFont(new Font("SansSerif", Font.PLAIN, 13));
        b.setForeground(Color.WHITE); b.setBackground(bg);
        b.putClientProperty("pill.restBg", bg);
        b.putClientProperty("pill.hoverBg", hover);
        b.setFocusPainted(false); b.setBorderPainted(false);
        b.setContentAreaFilled(false); b.setOpaque(false);
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.setBorder(new EmptyBorder(5, 12, 5, 12));
        b.addMouseListener(new MouseAdapter() {
            @Override public void mouseEntered(MouseEvent e) {
                b.setBackground((Color) b.getClientProperty("pill.hoverBg"));
            }
            @Override public void mouseExited(MouseEvent e) {
                b.setBackground((Color) b.getClientProperty("pill.restBg"));
            }
        });
        return b;
    }

    // ─── Dark scrollbar ──────────────────────────────────────────────────────

    private static class DarkScrollBarUI extends javax.swing.plaf.basic.BasicScrollBarUI {
        @Override protected void configureScrollBarColors() {
            thumbColor = new Color(62, 68, 82); trackColor = BG;
        }
        @Override protected JButton createDecreaseButton(int o) { return zeroBtn(); }
        @Override protected JButton createIncreaseButton(int o) { return zeroBtn(); }
        private JButton zeroBtn() { JButton b = new JButton(); b.setPreferredSize(new Dimension(0, 0)); return b; }
        @Override protected void paintThumb(Graphics g, JComponent c, Rectangle r) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(thumbColor); g2.fillRoundRect(r.x + 2, r.y + 2, r.width - 4, r.height - 4, 6, 6);
            g2.dispose();
        }
        @Override protected void paintTrack(Graphics g, JComponent c, Rectangle r) {
            g.setColor(trackColor); g.fillRect(r.x, r.y, r.width, r.height);
        }
    }
}
