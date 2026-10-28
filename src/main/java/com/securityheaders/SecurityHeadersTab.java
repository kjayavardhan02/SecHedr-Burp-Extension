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

import com.securityheaders.policy.*;
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
    private static final String[] COV_HEADER_KEYS = {
        "strict-transport-security", "cache-control", "x-frame-options",
        "x-content-type-options", "access-control-allow-origin", "content-security-policy"
    };
    private final JPanel[] dashCovBars = new JPanel[6];
    private final JLabel[] dashCovPcts = new JLabel[6];
    private final JLabel[] dashCovStats = new JLabel[6];
    private final int[] dashCovPresent = new int[6];
    private final int[] dashCovTotal = new int[6];

    // Dashboard testcase header coverage
    private final JPanel[] dashTcCovBars = new JPanel[6];
    private final JLabel[] dashTcCovPcts = new JLabel[6];
    private final JLabel[] dashTcCovStats = new JLabel[6];
    private final int[] dashTcCovPresent = new int[6];
    private final int[] dashTcCovTotal = new int[6];

    // Dashboard security posture
    private JLabel dashAffected, dashCompliant, dashCompliance, dashNoHeaders;

    // Dashboard scan health labels
    private JLabel dashProcessed, dashChecksMin, dashHeap, dashElapsed, dashLastUpdate, dashTcErrors;

    private final ResultsTableModel rawTableModel = new ResultsTableModel();
    private final HostSummaryTableModel hostTableModel = new HostSummaryTableModel();
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

    // Catalog filter
    private JTextField catalogSearchField;
    private JComboBox<String> catalogCategoryCombo;

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
    private JComboBox<String> tcStatusCodeCombo;
    private JTextField tcPathField;

    // Policy compliance filter
    private JComboBox<String> rawPolicyCombo;

    private List<HeaderResult> currentFiltered = new ArrayList<>();
    private List<HeaderResult> currentRepFiltered = new ArrayList<>();
    private List<TestcaseResult> currentTcFiltered = new ArrayList<>();
    private volatile boolean refreshingCombos = false;

    private final com.securityheaders.policy.PolicyStore policyStore;
    private final com.securityheaders.policy.PolicyEvaluator policyEvaluator;

    public SecurityHeadersTab(ResultStore resultStore, ResultStore repeaterResultStore,
                              ScopeManager scopeManager, HeaderCheckHttpHandler handler,
                              TestcaseLibrary library, TestcaseResultStore tcResultStore,
                              EndpointRegistry endpointRegistry, ApprovedBaseline baseline,
                              ActiveRunner activeRunner, TestcaseSelector selector,
                              ScanHealthTracker healthTracker,
                              com.securityheaders.policy.PolicyStore policyStore,
                              com.securityheaders.policy.PolicyEvaluator policyEvaluator) {
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
        this.policyStore = policyStore;
        this.policyEvaluator = policyEvaluator;
        this.tcTableModel = new TestcaseResultsTableModel(library);

        policyStore.setOnPolicyChange(() -> javax.swing.SwingUtilities.invokeLater(() -> {
            rawTableModel.invalidateEvalCache();
            rawTableModel.setPolicyContext(policyEvaluator, policyStore.getActive());
            repeaterTableModel.invalidateEvalCache();
            repeaterTableModel.setPolicyContext(policyEvaluator, policyStore.getActive());
            tcTableModel.invalidateEvalCache();
            tcTableModel.setPolicyContext(policyEvaluator, policyStore.getActive(), this::findHeaderResultForEndpoint);
            rawTableModel.fireTableDataChanged();
            repeaterTableModel.fireTableDataChanged();
            tcTableModel.fireTableDataChanged();
        }));

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
        tabs.addTab("Repeater Requests", createIcon(14, ACCENT, "repeat"), createRepeaterPanel(), null);
        tabs.addTab("Testcase Catalog", createIcon(14, TXT2, "list"), createCatalogPanel(), null);
        tabs.addTab("Testcase Results", createIcon(14, GREEN_FG, "check"), createTestcasePanel(), null);
        tabs.addTab("Policies", createIcon(14, WARN_FG, "gear"), createPoliciesPanel(), null);
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
        kpiRow.add(summaryCard("TC Errors / Inconclusive", dashErrors, RED_FG));

        dash.add(kpiRow);
        dash.add(Box.createVerticalStrut(24));

        // ── Header Coverage ──
        dash.add(dashSectionLabel("HEADER COVERAGE"));
        dash.add(Box.createVerticalStrut(6));

        JPanel covSplitPanel = new JPanel(new GridLayout(1, 2, 12, 0));
        covSplitPanel.setOpaque(false);
        covSplitPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        covSplitPanel.add(createCoverageCard("RAW RESULTS", dashCovBars, dashCovPcts,
                dashCovStats, dashCovPresent, dashCovTotal, true));
        covSplitPanel.add(createCoverageCard("TESTCASE RESULTS", dashTcCovBars, dashTcCovPcts,
                dashTcCovStats, dashTcCovPresent, dashTcCovTotal, false));

        covSplitPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 260));
        dash.add(covSplitPanel);
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
                    mainTabs.setSelectedIndex(1);
                    rawHeaderCombo.setSelectedIndex(1);
                }
            }
        });

        JPanel compliantCard = summaryCard("Fully Compliant", dashCompliant, GREEN_FG);
        compliantCard.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        compliantCard.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (mainTabs != null) {
                    mainTabs.setSelectedIndex(1);
                    rawHeaderCombo.setSelectedIndex(0);
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
        healthRow.add(summaryCard("Scan Failures", dashTcErrors, RED_FG));

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

    private JPanel createCoverageCard(String title, JPanel[] bars, JLabel[] pcts, JLabel[] stats,
                                       int[] present, int[] total, boolean isRaw) {
        JPanel card = new JPanel();
        card.setLayout(new BoxLayout(card, BoxLayout.Y_AXIS));
        card.setBackground(BG_ELEV);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER_S),
                new EmptyBorder(8, 10, 8, 10)));

        Color titleColor = isRaw ? ACCENT : GREEN_FG;
        JLabel titleLabel = new JLabel("  " + title);
        titleLabel.setFont(new Font("SansSerif", Font.BOLD, 11));
        titleLabel.setForeground(titleColor);
        titleLabel.setOpaque(true);
        titleLabel.setBackground(BG2);
        titleLabel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 2, 0, 0, titleColor),
                new EmptyBorder(4, 8, 4, 8)));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        titleLabel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 24));
        card.add(titleLabel);
        card.add(Box.createVerticalStrut(6));

        for (int i = 0; i < 6; i++) {
            pcts[i] = new JLabel("—");
            stats[i] = new JLabel("0 / 0");
            card.add(createCoverageRowGeneric(COV_LABELS[i], i, bars, pcts, stats, present, total, isRaw));
            if (i < 5) card.add(Box.createVerticalStrut(2));
        }
        return card;
    }

    private JPanel createCoverageRowGeneric(String headerName, int index,
                                             JPanel[] bars, JLabel[] pcts, JLabel[] stats,
                                             int[] present, int[] total, boolean isRaw) {
        JPanel row = new JPanel(new BorderLayout(6, 0));
        row.setBackground(BG2);
        row.setBorder(new EmptyBorder(3, 8, 3, 8));
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 26));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel name = new JLabel(headerName);
        name.setFont(new Font("SansSerif", Font.PLAIN, 11));
        name.setForeground(TXT);
        name.setPreferredSize(new Dimension(140, 18));

        final int idx = index;
        JPanel barTrack = new JPanel() {
            @Override protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(BORDER);
                g2.fillRoundRect(0, 2, getWidth(), getHeight() - 4, 6, 6);
                int t = total[idx];
                int p = present[idx];
                if (t > 0 && p > 0) {
                    int pctVal = p * 100 / t;
                    int barWidth = Math.max(4, (int) ((double) p / t * getWidth()));
                    Color barColor = pctVal >= 80 ? GREEN_FG : pctVal >= 50 ? WARN_FG : RED_FG;
                    g2.setColor(barColor);
                    g2.fillRoundRect(0, 2, barWidth, getHeight() - 4, 6, 6);
                }
                g2.dispose();
            }
        };
        barTrack.setOpaque(false);
        barTrack.setPreferredSize(new Dimension(150, 16));
        bars[index] = barTrack;

        pcts[index].setFont(new Font("SansSerif", Font.BOLD, 11));
        pcts[index].setForeground(TXT);
        pcts[index].setHorizontalAlignment(SwingConstants.RIGHT);
        pcts[index].setPreferredSize(new Dimension(40, 18));

        stats[index].setFont(new Font("SansSerif", Font.PLAIN, 10));
        stats[index].setForeground(TXT2);
        stats[index].setHorizontalAlignment(SwingConstants.RIGHT);
        stats[index].setPreferredSize(new Dimension(70, 18));

        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        rightPanel.setOpaque(false);
        rightPanel.add(pcts[index]);
        rightPanel.add(stats[index]);

        row.add(name, BorderLayout.WEST);
        row.add(barTrack, BorderLayout.CENTER);
        row.add(rightPanel, BorderLayout.EAST);

        row.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        final int tabIndex = isRaw ? 1 : 5;
        row.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (mainTabs != null) {
                    mainTabs.setSelectedIndex(tabIndex);
                    if (isRaw) rawHeaderCombo.setSelectedIndex(idx + 3);
                }
            }
            @Override public void mouseEntered(MouseEvent e) { row.setBackground(BG_ELEV); }
            @Override public void mouseExited(MouseEvent e) { row.setBackground(BG2); }
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

        // Testcase header coverage — parse responseData for header presence
        int[] tcPresent = new int[6];
        int tcCovCount = 0;
        for (TestcaseResult tr : tcAll) {
            if (tr.status() == ResultStatus.ERROR || tr.status() == ResultStatus.INCONCLUSIVE) continue;
            String resp = tr.responseData();
            if (resp == null || resp.isEmpty()) continue;
            tcCovCount++;
            String respLower = resp.toLowerCase(java.util.Locale.ROOT);
            for (int i = 0; i < 6; i++) {
                if (respLower.contains("\n" + COV_HEADER_KEYS[i] + ":")) tcPresent[i]++;
            }
        }
        for (int i = 0; i < 6; i++) {
            dashTcCovPresent[i] = tcPresent[i];
            dashTcCovTotal[i] = tcCovCount;
            int pctTc = tcCovCount > 0 ? tcPresent[i] * 100 / tcCovCount : 0;
            dashTcCovPcts[i].setText(pctTc + "%");
            dashTcCovStats[i].setText(tcPresent[i] + " / " + tcCovCount);
            dashTcCovBars[i].repaint();
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

        rawPolicyCombo = darkCombo(new String[]{"All", "PASS", "FAIL", "N/A", "NOT EVALUATED"});
        rawPolicyCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyRawFilters(); });
        bar.add(label("Policy")); bar.add(rawPolicyCombo);

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
        applyCenterRenderer(table, 11);
        applyCenterRenderer(table, 12);
        applyCenterRenderer(table, 13);
        applyComplianceRenderer(table, 14);

        JScrollPane tableSp = new JScrollPane(table);
        tableSp.setBorder(BorderFactory.createLineBorder(BORDER));
        tableSp.getViewport().setBackground(TBL_EVEN);
        tableSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        tableSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());

        // Request/Response detail
        JTextArea requestArea = darkTextArea();
        JTextArea responseArea = darkTextArea();
        JEditorPane policyDetailArea = new JEditorPane();
        policyDetailArea.setContentType("text/html");
        policyDetailArea.setEditable(false);
        policyDetailArea.setBackground(BG_INPUT);
        policyDetailArea.setForeground(TXT);
        policyDetailArea.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        policyDetailArea.setFont(new Font("SansSerif", Font.PLAIN, 13));

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
        respLabel.setForeground(ACCENT);
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

        JPanel policyPanel = new JPanel(new BorderLayout());
        policyPanel.setBackground(BG);
        JLabel policyLabel = new JLabel("  POLICY COMPLIANCE");
        policyLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        policyLabel.setForeground(ACCENT);
        policyLabel.setOpaque(true);
        policyLabel.setBackground(BG2);
        policyLabel.setBorder(new EmptyBorder(4, 8, 4, 8));
        JScrollPane policySp = new JScrollPane(policyDetailArea);
        policySp.setBorder(BorderFactory.createLineBorder(BORDER));
        policySp.getViewport().setBackground(BG_INPUT);
        policySp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        policySp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());
        policyPanel.add(policyLabel, BorderLayout.NORTH);
        policyPanel.add(policySp, BorderLayout.CENTER);

        JSplitPane reqRespSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, respPanel);
        reqRespSplit.setResizeWeight(0.5);
        reqRespSplit.setDividerSize(4);
        reqRespSplit.setBackground(BG);
        reqRespSplit.setBorder(null);

        JSplitPane detailSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqRespSplit, policyPanel);
        detailSplit.setResizeWeight(0.7);
        detailSplit.setDividerSize(4);
        detailSplit.setBackground(BG);
        detailSplit.setBorder(null);

        JPanel detailWrapper = new JPanel(new BorderLayout());
        detailWrapper.setBackground(BG);

        JPanel detailHeaderBar = new JPanel(new BorderLayout());
        detailHeaderBar.setBackground(BG2);
        detailHeaderBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER),
                new EmptyBorder(2, 12, 2, 4)));

        JLabel detailTitle = new JLabel("  Request / Response / Policy Compliance");
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

        JToggleButton wrapToggle = createWrapToggle(requestArea, responseArea);

        JPanel detailRightBtns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 2, 0));
        detailRightBtns.setOpaque(false);
        detailRightBtns.add(wrapToggle);
        detailRightBtns.add(closeDetailBtn);

        detailHeaderBar.add(detailTitle, BorderLayout.WEST);
        detailHeaderBar.add(detailRightBtns, BorderLayout.EAST);

        detailWrapper.add(detailHeaderBar, BorderLayout.NORTH);
        detailWrapper.add(detailSplit, BorderLayout.CENTER);

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
            policyDetailArea.setText("");
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
                policyDetailArea.setText("");
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

            policyDetailArea.setText(formatPolicyEvaluation(rawTableModel.getEvaluation(r)));
            policyDetailArea.setCaretPosition(0);

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

    // ─── Testcase Results Panel ──────────────────────────────────────────────

    private JPanel createTestcasePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(BG);
        panel.setBorder(new EmptyBorder(6, 10, 6, 10));

        // Testcase filter bar
        JPanel tcFilterBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4)) {
            @Override
            public Dimension getPreferredSize() {
                return wrapPreferredSize(this);
            }
        };
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
        tcStatusCodeCombo = darkCombo(new String[]{"None"});
        tcStatusCodeCombo.addItemListener(e -> { if (e.getStateChange() == ItemEvent.SELECTED && !refreshingCombos) applyTcFilters(); });

        tcFilterBar.add(label("Path")); tcFilterBar.add(tcPathField);
        tcFilterBar.add(label("Host")); tcFilterBar.add(tcHostCombo);
        tcFilterBar.add(label("Status Code")); tcFilterBar.add(tcStatusCodeCombo);
        tcFilterBar.add(label("Mode")); tcFilterBar.add(tcModeCombo);
        tcFilterBar.add(label("Result")); tcFilterBar.add(tcStatusCombo);
        tcFilterBar.add(label("Category")); tcFilterBar.add(tcCategoryCombo);

        JButton tcClear = pill("Reset", new Color(60, 64, 76), new Color(75, 80, 94));
        tcClear.addActionListener(e -> {
            tcPathField.setText("");
            tcHostCombo.setSelectedIndex(0);
            tcStatusCodeCombo.setSelectedIndex(0);
            tcModeCombo.setSelectedIndex(0);
            tcStatusCombo.setSelectedIndex(0);
            tcCategoryCombo.setSelectedIndex(0);
            applyTcFilters();
        });
        tcFilterBar.add(tcClear);

        JTable table = new JTable(tcTableModel);
        styleTable(table);
        applyTestcaseHeaderRenderer(table, 6, 9);
        applyTcAcaoColumnRenderer(table, 10);
        applyTcAcaoChecksRenderer(table, 11);
        applyTestcaseHeaderRenderer(table, 12, 12);
        applyComplianceRenderer(table, 13);
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

        JEditorPane tcPolicyDetailArea = new JEditorPane();
        tcPolicyDetailArea.setContentType("text/html");
        tcPolicyDetailArea.setEditable(false);
        tcPolicyDetailArea.setBackground(BG_INPUT);
        tcPolicyDetailArea.setForeground(TXT);
        tcPolicyDetailArea.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        tcPolicyDetailArea.setFont(new Font("SansSerif", Font.PLAIN, 13));

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
        respLabel.setForeground(ACCENT);
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

        JPanel tcPolicyPanel = new JPanel(new BorderLayout());
        tcPolicyPanel.setBackground(BG);
        JLabel tcPolicyLabel = new JLabel("  POLICY COMPLIANCE");
        tcPolicyLabel.setFont(new Font("SansSerif", Font.BOLD, 13));
        tcPolicyLabel.setForeground(ACCENT);
        tcPolicyLabel.setOpaque(true);
        tcPolicyLabel.setBackground(BG2);
        tcPolicyLabel.setBorder(new EmptyBorder(4, 8, 4, 8));
        JScrollPane tcPolicySp = new JScrollPane(tcPolicyDetailArea);
        tcPolicySp.setBorder(BorderFactory.createLineBorder(BORDER));
        tcPolicySp.getViewport().setBackground(BG_INPUT);
        tcPolicySp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        tcPolicySp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());
        tcPolicyPanel.add(tcPolicyLabel, BorderLayout.NORTH);
        tcPolicyPanel.add(tcPolicySp, BorderLayout.CENTER);

        JSplitPane reqRespSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, respPanel);
        reqRespSplit.setResizeWeight(0.5);
        reqRespSplit.setDividerSize(4);
        reqRespSplit.setBackground(BG);
        reqRespSplit.setBorder(null);

        JSplitPane tcDetailSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqRespSplit, tcPolicyPanel);
        tcDetailSplit.setResizeWeight(0.7);
        tcDetailSplit.setDividerSize(4);
        tcDetailSplit.setBackground(BG);
        tcDetailSplit.setBorder(null);

        // Detail wrapper with subtle close bar
        JPanel detailWrapper = new JPanel(new BorderLayout());
        detailWrapper.setBackground(BG);

        JPanel detailHeaderBar = new JPanel(new BorderLayout());
        detailHeaderBar.setBackground(BG2);
        detailHeaderBar.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, BORDER),
                new EmptyBorder(2, 12, 2, 4)));

        JLabel detailTitle = new JLabel("  Request / Response / Policy Compliance");
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

        JToggleButton wrapToggle = createWrapToggle(requestArea, responseArea);

        JPanel detailRightBtns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 2, 0));
        detailRightBtns.setOpaque(false);
        detailRightBtns.add(wrapToggle);
        detailRightBtns.add(closeDetailBtn);

        detailHeaderBar.add(detailTitle, BorderLayout.WEST);
        detailHeaderBar.add(detailRightBtns, BorderLayout.EAST);

        detailWrapper.add(detailHeaderBar, BorderLayout.NORTH);
        detailWrapper.add(tcDetailSplit, BorderLayout.CENTER);

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
            tcPolicyDetailArea.setText("");
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
                tcPolicyDetailArea.setText("");
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

            String reqText = headersOnly(r.requestData());
            String respText = headersOnly(r.responseData());
            requestArea.setText(reqText != null ? reqText : "(No request data captured)");
            responseArea.setText(respText != null ? respText : "(No response data captured)");
            requestArea.setCaretPosition(0);
            responseArea.setCaretPosition(0);

            HeaderResult matchedHr = findHeaderResultForEndpoint(r.endpointKey());
            if (matchedHr != null) {
                PolicyProfile active = policyStore.getActive();
                PolicyEvaluationResult evalResult = active != null
                        ? policyEvaluator.evaluate(matchedHr, active)
                        : PolicyEvaluationResult.notEvaluated();
                tcPolicyDetailArea.setText(formatPolicyEvaluation(evalResult));
            } else {
                tcPolicyDetailArea.setText(formatPolicyEvaluation(null));
            }
            tcPolicyDetailArea.setCaretPosition(0);

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
        applyCenterRenderer(table, 11);
        applyCenterRenderer(table, 12);
        applyCenterRenderer(table, 13);
        applyComplianceRenderer(table, 14);

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

        JToggleButton wrapToggle = createWrapToggle(requestArea, responseArea);

        JPanel detailRightBtns = new JPanel(new FlowLayout(FlowLayout.RIGHT, 2, 0));
        detailRightBtns.setOpaque(false);
        detailRightBtns.add(wrapToggle);
        detailRightBtns.add(closeDetailBtn);

        detailHeaderBar.add(detailTitle, BorderLayout.WEST);
        detailHeaderBar.add(detailRightBtns, BorderLayout.EAST);

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

    private JToggleButton createWrapToggle(JTextArea... areas) {
        JToggleButton btn = new JToggleButton("Wrap");
        btn.setFont(new Font("SansSerif", Font.PLAIN, 11));
        btn.setForeground(TXT_M);
        btn.setBackground(BG2);
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        btn.setContentAreaFilled(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setBorder(new EmptyBorder(2, 10, 2, 10));
        btn.setToolTipText("Toggle word wrap");
        btn.addActionListener(e -> {
            boolean wrap = btn.isSelected();
            btn.setForeground(wrap ? ACCENT : TXT_M);
            for (JTextArea area : areas) {
                area.setLineWrap(wrap);
                area.setWrapStyleWord(wrap);
            }
        });
        btn.addMouseListener(new MouseAdapter() {
            @Override public void mouseEntered(MouseEvent e) {
                if (!btn.isSelected()) btn.setForeground(TXT2);
            }
            @Override public void mouseExited(MouseEvent e) {
                btn.setForeground(btn.isSelected() ? ACCENT : TXT_M);
            }
        });
        return btn;
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
            catalogCategoryCombo.setSelectedIndex(0);
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

        catalogCategoryCombo = darkCombo(new String[]{"All"});
        JComboBox<String> catFilterCombo = catalogCategoryCombo;
        Set<String> cats = new TreeSet<>();
        for (TestcaseDefinition td : library.getAll()) {
            if (!td.category().isEmpty()) cats.add(td.category());
        }
        cats.forEach(catFilterCombo::addItem);
        catFilterCombo.addItemListener(e -> {
            if (e.getStateChange() == ItemEvent.SELECTED) applyCatalogFilter(catFilterCombo);
        });

        toolbar.add(label("Category"));
        toolbar.add(catFilterCombo);
        toolbar.add(Box.createHorizontalStrut(12));
        toolbar.add(selectAll);
        toolbar.add(deselectAll);

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

        void applyFilter(String search, String category) {
            filtered = allTcs.stream().filter(td -> {
                if (category != null && !"All".equals(category)) {
                    if (!td.category().equals(category)) return false;
                }
                if (search != null && !search.isBlank()) {
                    String lower = search.trim().toLowerCase();
                    return td.id().toLowerCase().contains(lower)
                        || td.name().toLowerCase().contains(lower)
                        || td.description().toLowerCase().contains(lower)
                        || td.category().toLowerCase().contains(lower);
                }
                return true;
            }).collect(Collectors.toList());
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

    // ─── Policies Panel ──────────────────────────────────────────────────────

    private JPanel createPoliciesPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBackground(BG);
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // --- Profile list table model ---
        String[] profileCols = {"Name", "Active", "Rules", "Version"};
        javax.swing.table.DefaultTableModel profileModel = new javax.swing.table.DefaultTableModel(profileCols, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
            @Override public Class<?> getColumnClass(int c) { return String.class; }
        };

        Runnable refreshProfiles = () -> {
            profileModel.setRowCount(0);
            for (PolicyProfile p : policyStore.getAll()) {
                profileModel.addRow(new Object[]{
                    p.name(),
                    p.active() ? "YES" : "",
                    String.valueOf(p.enabledRuleCount()),
                    "v" + p.version()
                });
            }
        };

        JTable profileTable = new JTable(profileModel);
        styleTable(profileTable);
        javax.swing.table.DefaultTableCellRenderer centerRenderer = new javax.swing.table.DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        for (int i = 0; i < profileTable.getColumnCount(); i++) {
            profileTable.getColumnModel().getColumn(i).setCellRenderer(centerRenderer);
        }
        profileTable.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        JScrollPane profileSp = new JScrollPane(profileTable);
        profileSp.setBorder(BorderFactory.createLineBorder(BORDER));
        profileSp.getViewport().setBackground(TBL_EVEN);
        profileSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        profileSp.setPreferredSize(new Dimension(300, 0));

        // --- Button bar ---
        JPanel btnBar = new JPanel(new BorderLayout());
        btnBar.setBackground(BG2);
        btnBar.setBorder(new EmptyBorder(4, 8, 4, 8));

        JPanel btnLeft = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        btnLeft.setOpaque(false);
        JPanel btnRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        btnRight.setOpaque(false);

        JButton createBtn = styledButton("Create");
        JButton defaultBtn = styledButton("Add Default");
        JButton duplicateBtn = styledButton("Duplicate");
        JButton deleteBtn = styledButton("Delete");

        JButton activateBtn = styledButton("Activate");
        activateBtn.setBackground(ACCENT_DIM);
        activateBtn.addMouseListener(new MouseAdapter() {
            @Override public void mouseEntered(MouseEvent e) { activateBtn.setBackground(ACCENT); }
            @Override public void mouseExited(MouseEvent e) { activateBtn.setBackground(ACCENT_DIM); }
        });

        JButton deactivateBtn = styledButton("Deactivate");
        deactivateBtn.setBackground(RED_BG);
        deactivateBtn.setForeground(RED_FG);
        deactivateBtn.addMouseListener(new MouseAdapter() {
            @Override public void mouseEntered(MouseEvent e) { deactivateBtn.setBackground(new Color(60, 28, 32)); }
            @Override public void mouseExited(MouseEvent e) { deactivateBtn.setBackground(RED_BG); }
        });

        btnLeft.add(createBtn);
        btnLeft.add(defaultBtn);
        btnLeft.add(duplicateBtn);
        btnLeft.add(deleteBtn);
        btnRight.add(activateBtn);
        btnRight.add(deactivateBtn);
        btnBar.add(btnLeft, BorderLayout.WEST);
        btnBar.add(btnRight, BorderLayout.EAST);

        // --- Editor panel (right side) ---
        JPanel editorPanel = new JPanel(new BorderLayout(0, 8));
        editorPanel.setBackground(BG);
        editorPanel.setBorder(new EmptyBorder(0, 10, 0, 0));

        JLabel editorTitle = new JLabel("Policy Editor");
        editorTitle.setFont(new Font("SansSerif", Font.BOLD, 14));
        editorTitle.setForeground(ACCENT);

        JPanel formPanel = new JPanel();
        formPanel.setLayout(new BoxLayout(formPanel, BoxLayout.Y_AXIS));
        formPanel.setBackground(BG);

        JTextField nameField = darkField(20);
        JTextField descField = darkField(30);

        JCheckBox hstsEnabled = darkCheckBox("HSTS");
        JTextField hstsMinAge = darkField(10);
        hstsMinAge.setText("31536000");
        JCheckBox hstsSubdomains = darkCheckBox("Require includeSubDomains");
        JCheckBox hstsPreload = darkCheckBox("Require preload");

        JCheckBox ccEnabled = darkCheckBox("Cache-Control");
        JPanel ccConditionsPanel = new JPanel();
        ccConditionsPanel.setLayout(new BoxLayout(ccConditionsPanel, BoxLayout.Y_AXIS));
        ccConditionsPanel.setBackground(BG);
        List<JPanel> ccConditionRows = new ArrayList<>();
        List<JTextField[]> ccConditionFields = new ArrayList<>();

        Runnable addCcConditionRow = () -> {
            JPanel row = new JPanel();
            row.setLayout(new BoxLayout(row, BoxLayout.Y_AXIS));
            row.setBackground(BG_ELEV);
            row.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(0, 0, 1, 0, BORDER),
                    new EmptyBorder(6, 8, 6, 8)));

            JTextField labelF = darkField(10);
            labelF.setToolTipText("Label (e.g. Static, HTML, API)");
            JTextField ctF = darkField(18);
            ctF.setToolTipText("Content-Type patterns, comma-separated (e.g. image/*,text/css). Leave empty for default/fallback.");
            JTextField reqF = darkField(18);
            reqF.setToolTipText("Comma-separated required directives (e.g. no-store,no-cache)");
            JTextField prohF = darkField(18);
            prohF.setToolTipText("Comma-separated prohibited directives (e.g. public)");

            JButton removeBtn = new JButton("Remove");
            removeBtn.setFont(new Font("SansSerif", Font.PLAIN, 11));
            removeBtn.setForeground(RED_FG);
            removeBtn.setBackground(BG);
            removeBtn.setBorderPainted(false);
            removeBtn.setFocusPainted(false);
            removeBtn.setContentAreaFilled(false);
            removeBtn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

            JPanel topRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            topRow.setOpaque(false);
            topRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 32));
            JLabel lbl1 = new JLabel("Label:"); lbl1.setForeground(TXT2); lbl1.setFont(new Font("SansSerif", Font.PLAIN, 11));
            JLabel lbl2 = new JLabel("Content-Type:"); lbl2.setForeground(TXT2); lbl2.setFont(new Font("SansSerif", Font.PLAIN, 11));
            topRow.add(lbl1); topRow.add(labelF);
            topRow.add(Box.createHorizontalStrut(6));
            topRow.add(lbl2); topRow.add(ctF);
            topRow.add(Box.createHorizontalStrut(6));
            topRow.add(removeBtn);

            JPanel bottomRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
            bottomRow.setOpaque(false);
            bottomRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 32));
            JLabel lbl3 = new JLabel("Required:"); lbl3.setForeground(TXT2); lbl3.setFont(new Font("SansSerif", Font.PLAIN, 11));
            JLabel lbl4 = new JLabel("Prohibited:"); lbl4.setForeground(TXT2); lbl4.setFont(new Font("SansSerif", Font.PLAIN, 11));
            bottomRow.add(lbl3); bottomRow.add(reqF);
            bottomRow.add(Box.createHorizontalStrut(6));
            bottomRow.add(lbl4); bottomRow.add(prohF);

            row.add(topRow);
            row.add(Box.createVerticalStrut(2));
            row.add(bottomRow);

            JTextField[] fields = {labelF, ctF, reqF, prohF};
            ccConditionRows.add(row);
            ccConditionFields.add(fields);
            ccConditionsPanel.add(row);
            ccConditionsPanel.add(Box.createVerticalStrut(4));
            ccConditionsPanel.revalidate();
            ccConditionsPanel.repaint();

            removeBtn.addActionListener(ev2 -> {
                int idx = ccConditionRows.indexOf(row);
                if (idx >= 0) {
                    ccConditionRows.remove(idx);
                    ccConditionFields.remove(idx);
                    ccConditionsPanel.remove(row);
                    ccConditionsPanel.revalidate();
                    ccConditionsPanel.repaint();
                }
            });
        };

        JButton addConditionBtn = styledButton("+ Add Condition");
        addConditionBtn.addActionListener(ev -> addCcConditionRow.run());

        JCheckBox xfoEnabled = darkCheckBox("X-Frame-Options");
        JTextField xfoAllowed = darkField(20);
        xfoAllowed.setToolTipText("Comma-separated allowed values (e.g. DENY,SAMEORIGIN)");

        JCheckBox xctoEnabled = darkCheckBox("X-Content-Type-Options");
        JTextField xctoExpected = darkField(15);
        xctoExpected.setText("nosniff");

        JCheckBox acaoEnabled = darkCheckBox("ACAO");
        JTextField acaoOrigins = darkField(25);
        acaoOrigins.setToolTipText("Comma-separated allowed origins (e.g. https://example.com)");
        JCheckBox acaoWildcard = darkCheckBox("Allow wildcard (*)");
        JCheckBox acaoNull = darkCheckBox("Allow null");

        JButton saveBtn = styledButton("Save Policy");
        JLabel editorStatus = new JLabel(" ");
        editorStatus.setForeground(GREEN_FG);
        editorStatus.setFont(new Font("SansSerif", Font.PLAIN, 12));

        // Layout the form
        formPanel.add(formRow("Name:", nameField));
        formPanel.add(formRow("Description:", descField));
        formPanel.add(Box.createVerticalStrut(10));
        formPanel.add(sectionLabel("HSTS"));
        formPanel.add(checkRow(hstsEnabled));
        formPanel.add(formRow("  max-age:", hstsMinAge));
        formPanel.add(checkRow(hstsSubdomains));
        formPanel.add(checkRow(hstsPreload));
        formPanel.add(Box.createVerticalStrut(8));
        formPanel.add(sectionLabel("Cache-Control"));
        formPanel.add(checkRow(ccEnabled));
        formPanel.add(Box.createVerticalStrut(4));
        formPanel.add(ccConditionsPanel);
        formPanel.add(Box.createVerticalStrut(6));
        JPanel addCondBtnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        addCondBtnRow.setBackground(BG);
        addCondBtnRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 36));
        addCondBtnRow.add(addConditionBtn);
        formPanel.add(addCondBtnRow);
        formPanel.add(Box.createVerticalStrut(8));
        formPanel.add(sectionLabel("X-Frame-Options"));
        formPanel.add(checkRow(xfoEnabled));
        formPanel.add(formRow("  Allowed:", xfoAllowed));
        formPanel.add(Box.createVerticalStrut(8));
        formPanel.add(sectionLabel("X-Content-Type-Options"));
        formPanel.add(checkRow(xctoEnabled));
        formPanel.add(formRow("  Expected:", xctoExpected));
        formPanel.add(Box.createVerticalStrut(8));
        formPanel.add(sectionLabel("ACAO"));
        formPanel.add(checkRow(acaoEnabled));
        formPanel.add(formRow("  Origins:", acaoOrigins));
        formPanel.add(checkRow(acaoWildcard));
        formPanel.add(checkRow(acaoNull));
        formPanel.add(Box.createVerticalStrut(12));

        JPanel saveBtnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        saveBtnRow.setBackground(BG);
        saveBtnRow.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        saveBtnRow.add(saveBtn);
        saveBtnRow.add(editorStatus);
        formPanel.add(saveBtnRow);

        JScrollPane formSp = new JScrollPane(formPanel);
        formSp.setBorder(BorderFactory.createLineBorder(BORDER));
        formSp.getViewport().setBackground(BG);
        formSp.getVerticalScrollBar().setUI(new DarkScrollBarUI());
        formSp.getHorizontalScrollBar().setUI(new DarkScrollBarUI());

        editorPanel.add(editorTitle, BorderLayout.NORTH);
        editorPanel.add(formSp, BorderLayout.CENTER);

        // --- Load profile into editor ---
        final String[] editingProfileId = {null};

        Runnable loadSelectedProfile = () -> {
            int row = profileTable.getSelectedRow();
            if (row < 0) return;
            List<PolicyProfile> all = policyStore.getAll();
            if (row >= all.size()) return;
            PolicyProfile p = all.get(row);
            editingProfileId[0] = p.id();
            nameField.setText(p.name());
            descField.setText(p.description() != null ? p.description() : "");

            PolicyRule hsts = p.getRule("strict-transport-security");
            if (hsts != null) {
                hstsEnabled.setSelected(hsts.enabled());
                hstsMinAge.setText(String.valueOf(hsts.minMaxAge()));
                hstsSubdomains.setSelected(hsts.requireIncludeSubDomains());
                hstsPreload.setSelected(hsts.requirePreload());
            } else {
                hstsEnabled.setSelected(false);
                hstsMinAge.setText("31536000");
                hstsSubdomains.setSelected(false);
                hstsPreload.setSelected(false);
            }

            PolicyRule cc = p.getRule("cache-control");
            ccConditionRows.clear();
            ccConditionFields.clear();
            ccConditionsPanel.removeAll();
            if (cc != null) {
                ccEnabled.setSelected(cc.enabled());
                if (cc.hasConditions()) {
                    for (CacheControlCondition c : cc.cacheControlConditions()) {
                        addCcConditionRow.run();
                        JTextField[] f = ccConditionFields.get(ccConditionFields.size() - 1);
                        f[0].setText(c.label());
                        f[1].setText(String.join(",", c.contentTypePatterns()));
                        f[2].setText(String.join(",", c.requiredDirectives()));
                        f[3].setText(String.join(",", c.prohibitedDirectives()));
                    }
                } else if (!cc.requiredDirectives().isEmpty() || !cc.prohibitedDirectives().isEmpty()) {
                    addCcConditionRow.run();
                    JTextField[] f = ccConditionFields.get(0);
                    f[0].setText("default");
                    f[1].setText("");
                    f[2].setText(String.join(",", cc.requiredDirectives()));
                    f[3].setText(String.join(",", cc.prohibitedDirectives()));
                }
            } else {
                ccEnabled.setSelected(false);
            }
            ccConditionsPanel.revalidate();
            ccConditionsPanel.repaint();

            PolicyRule xfo = p.getRule("x-frame-options");
            if (xfo != null) {
                xfoEnabled.setSelected(xfo.enabled());
                xfoAllowed.setText(String.join(",", xfo.allowedValues()));
            } else {
                xfoEnabled.setSelected(false);
                xfoAllowed.setText("");
            }

            PolicyRule xcto = p.getRule("x-content-type-options");
            if (xcto != null) {
                xctoEnabled.setSelected(xcto.enabled());
                xctoExpected.setText(xcto.expectedValue() != null ? xcto.expectedValue() : "");
            } else {
                xctoEnabled.setSelected(false);
                xctoExpected.setText("nosniff");
            }

            PolicyRule acao = p.getRule("access-control-allow-origin");
            if (acao != null) {
                acaoEnabled.setSelected(acao.enabled());
                acaoOrigins.setText(String.join(",", acao.allowedOrigins()));
                acaoWildcard.setSelected(acao.allowWildcard());
                acaoNull.setSelected(acao.allowNull());
            } else {
                acaoEnabled.setSelected(false);
                acaoOrigins.setText("");
                acaoWildcard.setSelected(false);
                acaoNull.setSelected(false);
            }
            editorStatus.setText(" ");
        };

        profileTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) loadSelectedProfile.run();
        });

        // --- Save button ---
        saveBtn.addActionListener(ev -> {
            if (editingProfileId[0] == null) {
                editorStatus.setForeground(RED_FG);
                editorStatus.setText("No profile selected.");
                return;
            }
            PolicyProfile p = policyStore.getById(editingProfileId[0]);
            if (p == null) {
                editorStatus.setForeground(RED_FG);
                editorStatus.setText("Profile not found.");
                return;
            }
            p.setName(nameField.getText().trim());
            p.setDescription(descField.getText().trim());

            long minAge;
            try { minAge = Long.parseLong(hstsMinAge.getText().trim()); }
            catch (NumberFormatException ex) { minAge = 31536000; }
            p.putRule(PolicyRule.hsts(hstsEnabled.isSelected(), minAge,
                    hstsSubdomains.isSelected(), hstsPreload.isSelected()));
            if (!ccConditionFields.isEmpty()) {
                List<CacheControlCondition> conditions = new ArrayList<>();
                for (JTextField[] f : ccConditionFields) {
                    conditions.add(new CacheControlCondition(
                            f[0].getText().trim(),
                            splitCsv(f[1].getText()),
                            splitCsv(f[2].getText()),
                            splitCsv(f[3].getText())));
                }
                p.putRule(PolicyRule.cacheControl(ccEnabled.isSelected(), conditions));
            } else {
                p.putRule(PolicyRule.cacheControl(ccEnabled.isSelected(), List.of(), List.of()));
            }
            p.putRule(PolicyRule.xFrameOptions(xfoEnabled.isSelected(),
                    splitCsv(xfoAllowed.getText())));
            p.putRule(PolicyRule.xContentTypeOptions(xctoEnabled.isSelected(),
                    xctoExpected.getText().trim()));
            p.putRule(PolicyRule.acao(acaoEnabled.isSelected(),
                    splitCsv(acaoOrigins.getText()), acaoWildcard.isSelected(), acaoNull.isSelected()));

            List<String> errors = p.validate();
            if (!errors.isEmpty()) {
                editorStatus.setForeground(RED_FG);
                editorStatus.setText(errors.get(0));
                return;
            }
            policyStore.update(p);
            refreshProfiles.run();
            editorStatus.setForeground(GREEN_FG);
            editorStatus.setText("Saved v" + p.version());
        });

        // --- Create ---
        createBtn.addActionListener(ev -> {
            String name = JOptionPane.showInputDialog(panel, "Policy name:", "Create Policy",
                    JOptionPane.PLAIN_MESSAGE);
            if (name == null || name.isBlank()) return;
            PolicyProfile p = new PolicyProfile(name.trim(), "");
            p.putRule(PolicyRule.hsts(true, 31536000, true, false));
            p.putRule(PolicyRule.cacheControl(true, List.of("no-store"), List.of()));
            p.putRule(PolicyRule.xFrameOptions(true, List.of("DENY", "SAMEORIGIN")));
            p.putRule(PolicyRule.xContentTypeOptions(true, "nosniff"));
            p.putRule(PolicyRule.acao(true, List.of(), false, false));
            policyStore.add(p);
            refreshProfiles.run();
            profileTable.setRowSelectionInterval(profileModel.getRowCount() - 1, profileModel.getRowCount() - 1);
        });

        // --- Add Default ---
        defaultBtn.addActionListener(ev -> {
            PolicyProfile d = PolicyProfile.defaultBaseline();
            policyStore.add(d);
            refreshProfiles.run();
            profileTable.setRowSelectionInterval(profileModel.getRowCount() - 1, profileModel.getRowCount() - 1);
        });

        // --- Duplicate ---
        duplicateBtn.addActionListener(ev -> {
            int row = profileTable.getSelectedRow();
            if (row < 0) return;
            List<PolicyProfile> all = policyStore.getAll();
            if (row >= all.size()) return;
            PolicyProfile orig = all.get(row);
            PolicyProfile dup = orig.duplicate(orig.name() + " (copy)");
            policyStore.add(dup);
            refreshProfiles.run();
            profileTable.setRowSelectionInterval(profileModel.getRowCount() - 1, profileModel.getRowCount() - 1);
        });

        // --- Activate ---
        activateBtn.addActionListener(ev -> {
            int row = profileTable.getSelectedRow();
            if (row < 0) return;
            List<PolicyProfile> all = policyStore.getAll();
            if (row >= all.size()) return;
            policyStore.activate(all.get(row).id());
            refreshProfiles.run();
        });

        // --- Deactivate ---
        deactivateBtn.addActionListener(ev -> {
            policyStore.deactivateAll();
            refreshProfiles.run();
        });

        // --- Delete ---
        deleteBtn.addActionListener(ev -> {
            int row = profileTable.getSelectedRow();
            if (row < 0) return;
            List<PolicyProfile> all = policyStore.getAll();
            if (row >= all.size()) return;
            PolicyProfile p = all.get(row);
            int confirm = JOptionPane.showConfirmDialog(panel,
                    "Delete policy \"" + p.name() + "\"?", "Confirm Delete",
                    JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) {
                policyStore.remove(p.id());
                editingProfileId[0] = null;
                refreshProfiles.run();
            }
        });

        // --- Layout ---
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBackground(BG);
        leftPanel.add(btnBar, BorderLayout.NORTH);
        leftPanel.add(profileSp, BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, editorPanel);
        split.setResizeWeight(0.35);
        split.setDividerSize(4);
        split.setBackground(BG);
        split.setBorder(null);

        panel.add(split, BorderLayout.CENTER);

        refreshProfiles.run();
        return panel;
    }

    private static List<String> splitCsv(String text) {
        if (text == null || text.isBlank()) return List.of();
        return Arrays.stream(text.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(java.util.stream.Collectors.toList());
    }

    private JPanel formRow(String labelText, JComponent field) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        row.setBackground(BG);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 34));
        JLabel l = new JLabel(labelText);
        l.setForeground(TXT2);
        l.setFont(new Font("SansSerif", Font.PLAIN, 12));
        row.add(l);
        row.add(field);
        return row;
    }

    private JPanel checkRow(JCheckBox cb) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 1));
        row.setBackground(BG);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));
        row.add(cb);
        return row;
    }

    private JPanel sectionLabel(String text) {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        row.setBackground(BG);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 26));
        JLabel l = new JLabel(text);
        l.setForeground(ACCENT);
        l.setFont(new Font("SansSerif", Font.BOLD, 13));
        row.add(l);
        return row;
    }

    private JCheckBox darkCheckBox(String text) {
        JCheckBox cb = new JCheckBox(text);
        cb.setBackground(BG);
        cb.setForeground(TXT);
        cb.setFont(new Font("SansSerif", Font.PLAIN, 12));
        cb.setFocusPainted(false);
        return cb;
    }

    private JButton styledButton(String text) {
        JButton btn = new JButton(text);
        btn.setFont(new Font("SansSerif", Font.BOLD, 12));
        btn.setForeground(TXT);
        btn.setBackground(BTN_MUTED);
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        btn.setBorder(new EmptyBorder(6, 14, 6, 14));
        btn.addMouseListener(new MouseAdapter() {
            @Override public void mouseEntered(MouseEvent e) { btn.setBackground(BTN_MUTED_H); }
            @Override public void mouseExited(MouseEvent e) { btn.setBackground(BTN_MUTED); }
        });
        return btn;
    }

    // ─── Scope & Export Panel ─────────────────────────────────────────────────

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

        } finally {
            refreshingCombos = false;
        }

        applyRawFilters();
        applyHostFilters();
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
            Set<Integer> statusCodes = new TreeSet<>();
            for (TestcaseResult r : all) {
                if (r.host() != null && !r.host().isEmpty()) hosts.add(r.host());
                if (r.statusCode() > 0) statusCodes.add(r.statusCode());
                String tcId = r.testcaseId();
                TestcaseDefinition def = library.get(tcId);
                if (def != null && !def.category().isEmpty()) categories.add(def.category());
            }
            String selHost = (String) tcHostCombo.getSelectedItem();
            tcHostCombo.removeAllItems();
            tcHostCombo.addItem("None");
            hosts.forEach(tcHostCombo::addItem);
            if (selHost != null && hosts.contains(selHost)) tcHostCombo.setSelectedItem(selHost);

            String selCode = (String) tcStatusCodeCombo.getSelectedItem();
            tcStatusCodeCombo.removeAllItems();
            tcStatusCodeCombo.addItem("None");
            statusCodes.forEach(c -> tcStatusCodeCombo.addItem(String.valueOf(c)));
            if (selCode != null && !"None".equals(selCode)) {
                for (int i = 0; i < tcStatusCodeCombo.getItemCount(); i++) {
                    if (tcStatusCodeCombo.getItemAt(i).equals(selCode)) {
                        tcStatusCodeCombo.setSelectedIndex(i);
                        break;
                    }
                }
            }

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

        // Update TC columns in Raw Results and Repeater tables
        List<TestcaseResult> tcAll = tcResultStore.getAll();
        rawTableModel.setTestcaseCounts(tcAll, library.size(), library);
        rawTableModel.fireTableDataChanged();
        repeaterTableModel.setTestcaseCounts(tcAll, library.size(), library);
        repeaterTableModel.fireTableDataChanged();
    }

    private void applyRawFilters() {
        List<HeaderResult> all = resultStore.getAll();
        FilterState fs = buildRawFilterState();
        rawTableModel.setPolicyContext(policyEvaluator, policyStore.getActive());
        currentFiltered = filterService.apply(all, fs, rawTableModel::getComplianceStatus);
        rawTableModel.setTestcaseCounts(tcResultStore.getAll(), library.size(), library);
        rawTableModel.setData(currentFiltered);
        rawFilterIndicator.setText(fs.isActive() ? "Filtered" : "");
    }

    private void applyRepeaterFilters() {
        List<HeaderResult> all = repeaterResultStore.getAll();
        FilterState fs = buildRepeaterFilterState();
        currentRepFiltered = filterService.apply(all, fs);
        repeaterTableModel.setTestcaseCounts(tcResultStore.getAll(), library.size(), library);
        repeaterTableModel.setData(currentRepFiltered);
        repFilterIndicator.setText(fs.isActive() ? "Filtered" : "");
    }

    private void applyTcFilters() {
        List<TestcaseResult> all = tcResultStore.getAll();
        tcTableModel.setPolicyContext(policyEvaluator, policyStore.getActive(), this::findHeaderResultForEndpoint);

        String pathFilter = tcPathField.getText().trim().toLowerCase();
        String hostFilter = tcHostCombo.getSelectedIndex() <= 0 ? null : (String) tcHostCombo.getSelectedItem();
        String statusCodeFilter = tcStatusCodeCombo.getSelectedIndex() <= 0 ? null : (String) tcStatusCodeCombo.getSelectedItem();
        String modeFilter = (String) tcModeCombo.getSelectedItem();
        String statusFilter = (String) tcStatusCombo.getSelectedItem();
        String catFilter = (String) tcCategoryCombo.getSelectedItem();

        currentTcFiltered = all.stream().filter(r -> {
            if (!pathFilter.isEmpty()) {
                String pq = r.pathAndQuery();
                if (pq == null || !pq.toLowerCase().contains(pathFilter)) return false;
            }
            if (hostFilter != null && !hostFilter.equalsIgnoreCase(r.host())) return false;
            if (statusCodeFilter != null) {
                try {
                    int code = Integer.parseInt(statusCodeFilter);
                    if (r.statusCode() != code) return false;
                } catch (NumberFormatException ignored) {}
            }
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
        rawPolicyCombo.setSelectedIndex(0);
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

    private void applyCatalogSearch() {
        String cat = (String) catalogCategoryCombo.getSelectedItem();
        catalogModel.applyFilter(catalogSearchField.getText(), cat);
    }

    private void applyCatalogFilter(JComboBox<String> combo) {
        String cat = (String) combo.getSelectedItem();
        catalogModel.applyFilter(catalogSearchField.getText(), cat);
    }

    private FilterState buildRawFilterState() {
        FilterState base = buildFilterState(rawSearchField, rawHostCombo, rawStatusCombo, rawHeaderCombo);
        String policyFilter = rawPolicyCombo.getSelectedIndex() <= 0 ? null : (String) rawPolicyCombo.getSelectedItem();
        return new FilterState(base.searchText(), base.hostFilter(), base.statusCodes(), base.headerFilter(), policyFilter);
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

    private String formatPolicyEvaluation(PolicyEvaluationResult eval) {
        if (eval == null || eval.overallStatus() == PolicyComplianceStatus.NOT_EVALUATED) {
            return "<html><body style='font-family:SansSerif;color:#828898;padding:10px;'>"
                    + "No active policy or evaluation not available.</body></html>";
        }

        String overallColor = switch (eval.overallStatus()) {
            case PASS -> "#4caf6e";
            case FAIL -> "#d25f64";
            case NA -> "#828898";
            default -> "#828898";
        };
        String overallLabel = eval.overallStatus().displayLabel();
        String policyName = eval.policyName() != null ? htmlEscape(eval.policyName()) : "Policy";

        StringBuilder sb = new StringBuilder();
        sb.append("<html><head><style>");
        sb.append("body{font-family:SansSerif;color:#c8ccd4;margin:0;padding:6px 8px;background:#1a1c23;}");
        sb.append(".policy-name{font-size:10px;color:#828898;margin-bottom:2px;}");
        sb.append(".header{font-size:11px;margin-bottom:6px;}");
        sb.append(".badge{display:inline;padding:1px 6px;border-radius:3px;font-weight:bold;font-size:9px;color:#fff;}");
        sb.append(".card{background:#1c1f26;border:1px solid #2e3340;border-radius:3px;padding:5px 8px;margin-bottom:4px;}");
        sb.append(".hdr-name{font-weight:bold;font-size:10px;color:#c8ccd4;}");
        sb.append(".lbl{color:#828898;font-size:9px;}");
        sb.append(".val{color:#c8ccd4;font-size:9px;font-family:monospace;}");
        sb.append(".pass{color:#4caf6e;font-weight:bold;font-size:9px;}");
        sb.append(".fail{color:#d25f64;font-weight:bold;font-size:9px;}");
        sb.append(".na{color:#828898;font-size:9px;}");
        sb.append("</style></head><body>");

        sb.append("<div class='policy-name'>Policy: <b style='color:#5892f0;'>").append(policyName).append("</b></div>");
        sb.append("<div class='header'>Policy Compliance")
          .append(" &nbsp;<span class='badge' style='background:").append(overallColor).append(";'>")
          .append(overallLabel).append("</span></div>");

        for (PolicyRuleResult rule : eval.ruleResults()) {
            String statusClass = switch (rule.status()) {
                case PASS -> "pass";
                case FAIL -> "fail";
                default -> "na";
            };
            String statusText = switch (rule.status()) {
                case PASS -> "&#10003; PASS";
                case FAIL -> "&#10007; FAIL";
                case NA -> "N/A";
                default -> "—";
            };

            sb.append("<div class='card'>");
            sb.append("<table width='100%' cellpadding='0' cellspacing='0'><tr>");
            sb.append("<td class='hdr-name'>").append(htmlEscape(rule.headerName())).append("</td>");
            sb.append("<td align='right' class='").append(statusClass).append("'>").append(statusText).append("</td>");
            sb.append("</tr></table>");

            if (rule.expectedDescription() != null) {
                sb.append("<div style='margin-top:3px;'><span class='lbl'>Expected: </span>");
                sb.append("<span class='val'>").append(htmlEscape(rule.expectedDescription())).append("</span></div>");
            }
            if (rule.actualValue() != null) {
                sb.append("<div style='margin-top:1px;'><span class='lbl'>Actual: </span>");
                sb.append("<span class='val'>").append(htmlEscape(rule.actualValue())).append("</span></div>");
            }
            sb.append("</div>");
        }

        sb.append("</body></html>");
        return sb.toString();
    }

    private static String htmlEscape(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    private HeaderResult findHeaderResultForEndpoint(String endpointKey) {
        if (endpointKey == null) return null;
        List<HeaderResult> all = resultStore.getAll();
        for (int i = all.size() - 1; i >= 0; i--) {
            if (endpointKey.equals(all.get(i).endpointKey())) return all.get(i);
        }
        return null;
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
                l.setVerticalAlignment(SwingConstants.CENTER);
                l.setText(val != null ? val.toString() : "");
                SortOrder order = null;
                if (t.getRowSorter() != null) {
                    int modelCol = t.convertColumnIndexToModel(col);
                    for (var sk : t.getRowSorter().getSortKeys()) {
                        if (sk.getColumn() == modelCol) {
                            order = sk.getSortOrder();
                            break;
                        }
                    }
                }
                if (order != null) {
                    boolean asc = order == SortOrder.ASCENDING;
                    int fontH = l.getFontMetrics(l.getFont()).getHeight();
                    l.setIconTextGap(4);
                    l.setHorizontalTextPosition(SwingConstants.LEADING);
                    l.setIcon(new Icon() {
                        final int w = 8, h = fontH, triH = 6;
                        @Override public int getIconWidth() { return w; }
                        @Override public int getIconHeight() { return h; }
                        @Override public void paintIcon(Component c, Graphics g, int x, int y) {
                            Graphics2D g2 = (Graphics2D) g.create();
                            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                            g2.setColor(ACCENT);
                            int top = y + (h - triH) / 2;
                            int[] xs = {x, x + w, x + w / 2};
                            int[] ys = asc ? new int[]{top + triH, top + triH, top} : new int[]{top, top, top + triH};
                            g2.fillPolygon(xs, ys, 3);
                            g2.dispose();
                        }
                    });
                } else {
                    l.setIcon(null);
                }
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

    private void applyTcAcaoColumnRenderer(JTable table, int col) {
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
                        case "FAIL" -> { l.setBackground(RED_BG); l.setForeground(RED_FG); }
                        case "MISSING" -> { l.setBackground(ORANGE_BG); l.setForeground(ORANGE_FG); }
                        case "COVERED", "ERROR", "INCONCLUSIVE" -> { l.setBackground(WARN_BG); l.setForeground(WARN_FG); }
                        default -> { l.setBackground(row % 2 == 0 ? TBL_EVEN : TBL_ODD); l.setForeground(TXT_M); }
                    }
                } else if (sel) { l.setBackground(TBL_SEL); l.setForeground(TXT); }
                return l;
            }
        };
        table.getColumnModel().getColumn(col).setCellRenderer(r);
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

    private void applyComplianceRenderer(JTable table, int col) {
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
                        case "PASS" -> { l.setBackground(GREEN_BG); l.setForeground(GREEN_FG); }
                        case "FAIL" -> { l.setBackground(RED_BG); l.setForeground(RED_FG); }
                        case "N/A" -> { l.setBackground(row % 2 == 0 ? TBL_EVEN : TBL_ODD); l.setForeground(TXT_M); }
                        default -> { l.setBackground(row % 2 == 0 ? TBL_EVEN : TBL_ODD); l.setForeground(TXT_M); l.setText("—"); }
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

    private static Dimension wrapPreferredSize(JPanel panel) {
        int w = panel.getParent() != null ? panel.getParent().getWidth() : 0;
        if (w == 0) return panel.getLayout().preferredLayoutSize(panel);
        Insets ins = panel.getInsets();
        FlowLayout fl = (FlowLayout) panel.getLayout();
        int maxW = w - ins.left - ins.right;
        int x = 0, y = 0, rowH = 0;
        for (Component c : panel.getComponents()) {
            Dimension d = c.getPreferredSize();
            if (x > 0 && x + fl.getHgap() + d.width > maxW) {
                y += rowH + fl.getVgap();
                x = 0;
                rowH = 0;
            }
            x += (x > 0 ? fl.getHgap() : 0) + d.width;
            rowH = Math.max(rowH, d.height);
        }
        y += rowH;
        return new Dimension(w, y + ins.top + ins.bottom + 2 * fl.getVgap());
    }

    private static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

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
