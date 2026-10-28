package com.securityheaders.policy;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

public class PolicyStore {

    private static final String FILE_NAME = ".burp_security_headers_policies.json";
    private final CopyOnWriteArrayList<PolicyProfile> profiles = new CopyOnWriteArrayList<>();
    private volatile Runnable onPolicyChange;
    private final Path storePath;
    private final Gson gson;

    public PolicyStore() {
        this.storePath = Paths.get(System.getProperty("user.home"), FILE_NAME);
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        load();
    }

    public void setOnPolicyChange(Runnable callback) {
        this.onPolicyChange = callback;
    }

    public List<PolicyProfile> getAll() {
        return Collections.unmodifiableList(new ArrayList<>(profiles));
    }

    public PolicyProfile getById(String id) {
        for (PolicyProfile p : profiles) {
            if (p.id().equals(id)) return p;
        }
        return null;
    }

    public PolicyProfile getActive() {
        for (PolicyProfile p : profiles) {
            if (p.active()) return p;
        }
        return null;
    }

    public void add(PolicyProfile profile) {
        profiles.add(profile);
        firePolicyChange();
    }

    public void remove(String id) {
        profiles.removeIf(p -> p.id().equals(id));
        firePolicyChange();
    }

    public void activate(String id) {
        for (PolicyProfile p : profiles) {
            p.setActive(p.id().equals(id));
        }
        firePolicyChange();
    }

    public void deactivateAll() {
        for (PolicyProfile p : profiles) {
            p.setActive(false);
        }
        firePolicyChange();
    }

    public void update(PolicyProfile profile) {
        profile.bumpVersion();
        firePolicyChange();
    }

    public int size() {
        return profiles.size();
    }

    private void firePolicyChange() {
        save();
        Runnable cb = onPolicyChange;
        if (cb != null) cb.run();
    }

    // ─── Persistence ─────────────────────────────────────────────────────────

    private void save() {
        try {
            JsonArray arr = new JsonArray();
            for (PolicyProfile p : profiles) {
                arr.add(serializeProfile(p));
            }
            Files.writeString(storePath, gson.toJson(arr), StandardCharsets.UTF_8);
        } catch (IOException ignored) {
        }
    }

    private void load() {
        if (!Files.exists(storePath)) return;
        try {
            String json = Files.readString(storePath, StandardCharsets.UTF_8);
            JsonArray arr = JsonParser.parseString(json).getAsJsonArray();
            for (JsonElement el : arr) {
                PolicyProfile p = deserializeProfile(el.getAsJsonObject());
                if (p != null) profiles.add(p);
            }
        } catch (Exception ignored) {
        }
    }

    private JsonObject serializeProfile(PolicyProfile p) {
        JsonObject o = new JsonObject();
        o.addProperty("id", p.id());
        o.addProperty("name", p.name());
        o.addProperty("description", p.description());
        o.addProperty("active", p.active());
        o.addProperty("version", p.version());
        o.addProperty("updatedAt", p.updatedAt().toString());

        JsonObject rulesObj = new JsonObject();
        for (Map.Entry<String, PolicyRule> entry : p.rules().entrySet()) {
            rulesObj.add(entry.getKey(), serializeRule(entry.getValue()));
        }
        o.add("rules", rulesObj);
        return o;
    }

    private JsonObject serializeRule(PolicyRule r) {
        JsonObject o = new JsonObject();
        o.addProperty("headerName", r.headerName());
        o.addProperty("enabled", r.enabled());
        o.addProperty("mode", r.mode().name());

        switch (r.headerName()) {
            case "strict-transport-security" -> {
                o.addProperty("minMaxAge", r.minMaxAge());
                o.addProperty("requireIncludeSubDomains", r.requireIncludeSubDomains());
                o.addProperty("requirePreload", r.requirePreload());
            }
            case "cache-control" -> {
                if (r.hasConditions()) {
                    JsonArray condArr = new JsonArray();
                    for (CacheControlCondition c : r.cacheControlConditions()) {
                        JsonObject co = new JsonObject();
                        co.addProperty("label", c.label());
                        co.add("contentTypePatterns", toJsonArray(c.contentTypePatterns()));
                        co.add("requiredDirectives", toJsonArray(c.requiredDirectives()));
                        co.add("prohibitedDirectives", toJsonArray(c.prohibitedDirectives()));
                        condArr.add(co);
                    }
                    o.add("conditions", condArr);
                } else {
                    o.add("requiredDirectives", toJsonArray(r.requiredDirectives()));
                    o.add("prohibitedDirectives", toJsonArray(r.prohibitedDirectives()));
                }
            }
            case "x-frame-options" -> {
                o.add("allowedValues", toJsonArray(r.allowedValues()));
            }
            case "x-content-type-options" -> {
                o.addProperty("expectedValue", r.expectedValue());
            }
            case "access-control-allow-origin" -> {
                o.add("allowedOrigins", toJsonArray(r.allowedOrigins()));
                o.addProperty("allowWildcard", r.allowWildcard());
                o.addProperty("allowNull", r.allowNull());
            }
            case "content-security-policy" -> {
                if (r.hasCspConditions()) {
                    JsonArray condArr = new JsonArray();
                    for (CacheControlCondition c : r.cspConditions()) {
                        JsonObject co = new JsonObject();
                        co.addProperty("label", c.label());
                        co.add("contentTypePatterns", toJsonArray(c.contentTypePatterns()));
                        co.add("requiredDirectives", toJsonArray(c.requiredDirectives()));
                        co.add("prohibitedSources", toJsonArray(c.prohibitedDirectives()));
                        condArr.add(co);
                    }
                    o.add("conditions", condArr);
                } else {
                    o.add("requiredDirectives", toJsonArray(r.cspRequiredDirectives()));
                    o.add("prohibitedSources", toJsonArray(r.cspProhibitedSources()));
                }
            }
        }
        return o;
    }

    private PolicyProfile deserializeProfile(JsonObject o) {
        String id = o.get("id").getAsString();
        String name = o.get("name").getAsString();
        String desc = o.has("description") && !o.get("description").isJsonNull()
                ? o.get("description").getAsString() : "";
        boolean active = o.has("active") && o.get("active").getAsBoolean();
        int version = o.has("version") ? o.get("version").getAsInt() : 1;
        Instant updatedAt = o.has("updatedAt")
                ? Instant.parse(o.get("updatedAt").getAsString()) : Instant.now();

        PolicyProfile p = new PolicyProfile(id, name, desc, active, version, updatedAt);

        if (o.has("rules") && o.get("rules").isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : o.getAsJsonObject("rules").entrySet()) {
                PolicyRule rule = deserializeRule(entry.getValue().getAsJsonObject());
                if (rule != null) p.putRule(rule);
            }
        }
        return p;
    }

    private PolicyRule deserializeRule(JsonObject o) {
        String header = o.get("headerName").getAsString();
        boolean enabled = o.has("enabled") && o.get("enabled").getAsBoolean();

        return switch (header) {
            case "strict-transport-security" -> PolicyRule.hsts(enabled,
                    o.has("minMaxAge") ? o.get("minMaxAge").getAsLong() : 31536000,
                    o.has("requireIncludeSubDomains") && o.get("requireIncludeSubDomains").getAsBoolean(),
                    o.has("requirePreload") && o.get("requirePreload").getAsBoolean());
            case "cache-control" -> {
                if (o.has("conditions") && o.get("conditions").isJsonArray()) {
                    List<CacheControlCondition> conditions = new ArrayList<>();
                    for (JsonElement el : o.getAsJsonArray("conditions")) {
                        JsonObject co = el.getAsJsonObject();
                        conditions.add(new CacheControlCondition(
                                co.has("label") ? co.get("label").getAsString() : "",
                                fromJsonArray(co, "contentTypePatterns"),
                                fromJsonArray(co, "requiredDirectives"),
                                fromJsonArray(co, "prohibitedDirectives")));
                    }
                    yield PolicyRule.cacheControl(enabled, conditions);
                } else {
                    yield PolicyRule.cacheControl(enabled,
                            fromJsonArray(o, "requiredDirectives"),
                            fromJsonArray(o, "prohibitedDirectives"));
                }
            }
            case "x-frame-options" -> PolicyRule.xFrameOptions(enabled,
                    fromJsonArray(o, "allowedValues"));
            case "x-content-type-options" -> PolicyRule.xContentTypeOptions(enabled,
                    o.has("expectedValue") ? o.get("expectedValue").getAsString() : "nosniff");
            case "access-control-allow-origin" -> PolicyRule.acao(enabled,
                    fromJsonArray(o, "allowedOrigins"),
                    o.has("allowWildcard") && o.get("allowWildcard").getAsBoolean(),
                    o.has("allowNull") && o.get("allowNull").getAsBoolean());
            case "content-security-policy" -> {
                if (o.has("conditions") && o.get("conditions").isJsonArray()) {
                    List<CacheControlCondition> conditions = new ArrayList<>();
                    for (JsonElement el : o.getAsJsonArray("conditions")) {
                        JsonObject co = el.getAsJsonObject();
                        conditions.add(new CacheControlCondition(
                                co.has("label") ? co.get("label").getAsString() : "",
                                fromJsonArray(co, "contentTypePatterns"),
                                fromJsonArray(co, "requiredDirectives"),
                                fromJsonArray(co, "prohibitedSources")));
                    }
                    yield PolicyRule.cspWithConditions(enabled, conditions);
                } else {
                    yield PolicyRule.csp(enabled,
                            fromJsonArray(o, "requiredDirectives"),
                            fromJsonArray(o, "prohibitedSources"));
                }
            }
            default -> null;
        };
    }

    private static JsonArray toJsonArray(List<String> list) {
        JsonArray arr = new JsonArray();
        for (String s : list) arr.add(s);
        return arr;
    }

    private static List<String> fromJsonArray(JsonObject o, String key) {
        List<String> list = new ArrayList<>();
        if (o.has(key) && o.get(key).isJsonArray()) {
            for (JsonElement el : o.getAsJsonArray(key)) {
                list.add(el.getAsString());
            }
        }
        return list;
    }
}
