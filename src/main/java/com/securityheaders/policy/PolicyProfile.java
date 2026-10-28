package com.securityheaders.policy;

import java.time.Instant;
import java.util.*;

public final class PolicyProfile {

    private final String id;
    private String name;
    private String description;
    private boolean active;
    private int version;
    private Instant updatedAt;
    private final Map<String, PolicyRule> rules = new LinkedHashMap<>();

    public PolicyProfile(String name, String description) {
        this.id = UUID.randomUUID().toString();
        this.name = name;
        this.description = description;
        this.version = 1;
        this.updatedAt = Instant.now();
    }

    PolicyProfile(String id, String name, String description, boolean active,
                  int version, Instant updatedAt) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.active = active;
        this.version = version;
        this.updatedAt = updatedAt;
    }

    public String id() { return id; }
    public String name() { return name; }
    public void setName(String name) { this.name = name; }
    public String description() { return description; }
    public void setDescription(String description) { this.description = description; }
    public boolean active() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public int version() { return version; }
    public Instant updatedAt() { return updatedAt; }
    public Map<String, PolicyRule> rules() { return rules; }

    public void putRule(PolicyRule rule) {
        rules.put(rule.headerName(), rule);
    }

    public PolicyRule getRule(String headerName) {
        return rules.get(headerName);
    }

    public int enabledRuleCount() {
        return (int) rules.values().stream().filter(PolicyRule::enabled).count();
    }

    public void bumpVersion() {
        this.version++;
        this.updatedAt = Instant.now();
    }

    public List<String> validate() {
        List<String> errors = new ArrayList<>();
        if (name == null || name.isBlank()) errors.add("Policy name is required");
        for (PolicyRule rule : rules.values()) {
            errors.addAll(rule.validate());
        }
        return errors;
    }

    public PolicyProfile duplicate(String newName) {
        PolicyProfile copy = new PolicyProfile(newName, description);
        copy.active = false;
        for (PolicyRule rule : rules.values()) {
            copy.putRule(rule.copy());
        }
        return copy;
    }

    public static PolicyProfile defaultBaseline() {
        PolicyProfile p = new PolicyProfile("Default Baseline",
                "Baseline policy checking common security header best practices");
        p.putRule(PolicyRule.hsts(true, 31536000, true, false));
        p.putRule(PolicyRule.cacheControl(true, List.of("no-store"), List.of()));
        p.putRule(PolicyRule.xFrameOptions(true, List.of("DENY", "SAMEORIGIN")));
        p.putRule(PolicyRule.xContentTypeOptions(true, "nosniff"));
        p.putRule(PolicyRule.acao(true, List.of(), false, false));
        return p;
    }
}
