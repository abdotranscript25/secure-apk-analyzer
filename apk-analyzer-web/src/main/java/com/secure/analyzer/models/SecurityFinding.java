package com.secure.analyzer.models;

import java.util.List;

public class SecurityFinding implements java.io.Serializable {
    private String id;
    private FindingType type;
    private String location;
    private List<String> sensitiveLabels;
    private String rawValueSnippet;
    private Severity severity;
    private String recommendation;
    private String codeExample;

    // Constructeur principal
    public SecurityFinding(FindingType type, String location,
                           List<String> sensitiveLabels, String rawValueSnippet,
                           Severity severity, String recommendation) {
        this.id = String.valueOf(System.currentTimeMillis());
        this.type = type;
        this.location = location;
        this.sensitiveLabels = sensitiveLabels;
        this.rawValueSnippet = rawValueSnippet;
        this.severity = severity;
        this.recommendation = recommendation;
        this.codeExample = "";
    }

    // Constructeur complet
    public SecurityFinding(String id, FindingType type, String location,
                           List<String> sensitiveLabels, String rawValueSnippet,
                           Severity severity, String recommendation, String codeExample) {
        this.id = id;
        this.type = type;
        this.location = location;
        this.sensitiveLabels = sensitiveLabels;
        this.rawValueSnippet = rawValueSnippet;
        this.severity = severity;
        this.recommendation = recommendation;
        this.codeExample = codeExample;
    }

    // ── Getters originaux ──────────────────────────────────────────────────────

    public String getId()                      { return id; }
    public FindingType getType()               { return type; }
    public String getLocation()                { return location; }
    public List<String> getSensitiveLabels()   { return sensitiveLabels; }
    public String getRawValueSnippet()         { return rawValueSnippet; }
    public Severity getSeverity()              { return severity; }
    public String getRecommendation()          { return recommendation; }
    public String getCodeExample()             { return codeExample; }

    // ── Alias ajoutés pour UltimateAnalyzer v3.0 ──────────────────────────────

    /** Alias de getLocation() — nom du fichier source du finding */
    public String getFileName()                { return location; }

    /** Alias de getRawValueSnippet() — valeur / extrait de code du finding */
    public String getEvidence()                { return rawValueSnippet; }

    // ── Setters ───────────────────────────────────────────────────────────────

    public void setCodeExample(String codeExample) { this.codeExample = codeExample; }
}