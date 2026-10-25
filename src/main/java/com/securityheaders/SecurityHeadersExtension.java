package com.securityheaders;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import com.securityheaders.testcase.*;

public class SecurityHeadersExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Security Headers");

        ResultStore resultStore = new ResultStore();
        ResultStore repeaterResultStore = new ResultStore();
        ScopeManager scopeManager = new ScopeManager();

        // V3 testcase components
        TestcaseLibrary library = new TestcaseLibrary();
        ApprovedBaseline baseline = new ApprovedBaseline();
        BaselineEvaluator evaluator = new BaselineEvaluator(baseline);
        TestcaseResultStore tcResultStore = new TestcaseResultStore();
        EndpointRegistry endpointRegistry = new EndpointRegistry();
        TestcaseSelector selector = new TestcaseSelector();
        PassiveEngine passiveEngine = new PassiveEngine(library, evaluator);
        passiveEngine.setTestcaseSelector(selector);
        ActiveRunner activeRunner = new ActiveRunner(api, library, evaluator,
                scopeManager, endpointRegistry, tcResultStore);
        activeRunner.setTestcaseSelector(selector);

        ScanHealthTracker healthTracker = new ScanHealthTracker();

        HeaderCheckHttpHandler handler = new HeaderCheckHttpHandler(resultStore, scopeManager);
        handler.setPassiveEngine(passiveEngine);
        handler.setActiveRunner(activeRunner);
        handler.setTestcaseResultStore(tcResultStore);
        handler.setEndpointRegistry(endpointRegistry);
        handler.setRepeaterResultStore(repeaterResultStore);
        handler.setHealthTracker(healthTracker);

        SecurityHeadersTab tab = new SecurityHeadersTab(resultStore, repeaterResultStore,
                scopeManager, handler, library, tcResultStore, endpointRegistry,
                baseline, activeRunner, selector, healthTracker);
        handler.setOnNewResult(tab::refreshViews);
        handler.setOnTestcaseResult(tab::refreshTestcaseViews);
        handler.setOnRepeaterResult(tab::refreshRepeaterViews);
        activeRunner.setOnResultsReady(tab::refreshTestcaseViews);

        api.http().registerHttpHandler(handler);
        api.userInterface().registerSuiteTab("SecHedr", tab);

        api.extension().registerUnloadingHandler(() -> activeRunner.shutdown());

        api.logging().logToOutput("Security Headers v4.0 extension loaded — "
                + library.size() + " testcases registered.");
    }
}
