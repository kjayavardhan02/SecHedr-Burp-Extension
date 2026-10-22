package com.securityheaders.testcase;

public final class TestcaseDefinition {

    private final String id;
    private final String name;
    private final String description;
    private final String category;
    private final ExecutionMode mode;
    private final SupportStatus supportStatus;
    private final String preconditions;
    private final String requestRequirements;
    private final String executionSteps;
    private final String expectedResult;
    private final String baselineReference;
    private final String unsupportedReason;

    public TestcaseDefinition(String id, String name, String description, String category,
                              ExecutionMode mode, SupportStatus supportStatus,
                              String preconditions, String requestRequirements,
                              String executionSteps, String expectedResult,
                              String baselineReference, String unsupportedReason) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.category = category;
        this.mode = mode;
        this.supportStatus = supportStatus;
        this.preconditions = preconditions;
        this.requestRequirements = requestRequirements;
        this.executionSteps = executionSteps;
        this.expectedResult = expectedResult;
        this.baselineReference = baselineReference;
        this.unsupportedReason = unsupportedReason;
    }

    public String id() { return id; }
    public String name() { return name; }
    public String description() { return description; }
    public String category() { return category; }
    public ExecutionMode mode() { return mode; }
    public SupportStatus supportStatus() { return supportStatus; }
    public String preconditions() { return preconditions; }
    public String requestRequirements() { return requestRequirements; }
    public String executionSteps() { return executionSteps; }
    public String expectedResult() { return expectedResult; }
    public String baselineReference() { return baselineReference; }
    public String unsupportedReason() { return unsupportedReason; }

    public boolean isPassive() {
        return mode == ExecutionMode.PASSIVE || mode == ExecutionMode.BOTH;
    }

    public boolean isActive() {
        return mode == ExecutionMode.ACTIVE || mode == ExecutionMode.BOTH;
    }
}
