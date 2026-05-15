package com.secure.analyzer.ai;

import com.secure.analyzer.analyzers.UltimateAnalyzer.UltimateReport;

import java.util.ArrayList;
import java.util.List;

public class AIBehaviorAnalyzer {

    // ============================================
    // RESULTAT IA
    // ============================================
    public static class AIResult {

        public String verdict;
        public int riskScore;

        public List<String> threats;
        public List<String> behaviors;

        public AIResult() {
            threats = new ArrayList<>();
            behaviors = new ArrayList<>();
        }
    }

    // ============================================
    // ANALYSE IA PRINCIPALE
    // ============================================
    public static AIResult analyze(UltimateReport report) {

        AIResult result = new AIResult();

        int score = 0;

        // ============================================
        // DETECTION FEATURES
        // ============================================

        boolean sms =
                report.dangerousPermissions.stream()
                        .anyMatch(p ->
                                p.contains("READ_SMS")
                                        || p.contains("SEND_SMS"));

        boolean internet =
                !report.urlsFound.isEmpty();

        boolean secrets =
                !report.hardcodedSecrets.isEmpty();

        boolean accessibility =
                report.dangerousPermissions.stream()
                        .anyMatch(p ->
                                p.contains("BIND_ACCESSIBILITY_SERVICE"));

        boolean microphone =
                report.dangerousPermissions.stream()
                        .anyMatch(p ->
                                p.contains("RECORD_AUDIO"));

        boolean camera =
                report.dangerousPermissions.stream()
                        .anyMatch(p ->
                                p.contains("CAMERA"));

        // ============================================
        // IA COMPORTEMENTALE
        // ============================================

        // Exfiltration données
        if (sms && internet && secrets) {

            score += 40;

            result.behaviors.add(
                    "Sensitive data exfiltration pattern detected"
            );

            result.threats.add(
                    "SMS data may be transmitted to external server"
            );
        }

        // Spyware
        if (accessibility && sms) {

            score += 50;

            result.behaviors.add(
                    "Spyware-like monitoring behavior detected"
            );

            result.threats.add(
                    "Accessibility service combined with SMS access"
            );
        }

        // Surveillance
        if (microphone && camera && internet) {

            score += 35;

            result.behaviors.add(
                    "Possible surveillance capabilities detected"
            );

            result.threats.add(
                    "Camera/microphone data could be streamed remotely"
            );
        }

        // ============================================
        // BONUS SELON LES FINDINGS + COMPORTEMENTS ASSOCIES
        score += report.criticalCount * 15;
        score += report.highCount * 8;
        score += report.mediumCount * 3;
        score += report.lowCount;

// Comportements dérivés des counts
        if (report.criticalCount >= 3) {
            result.behaviors.add(
                    "Multiple critical vulnerabilities suggest intentional risk"
            );
            result.threats.add(
                    report.criticalCount + " critical findings detected"
            );
        }

        if (report.highCount >= 3) {
            result.behaviors.add(
                    "High concentration of high-severity issues detected"
            );
            result.threats.add(
                    report.highCount + " high-severity findings — possible attack surface"
            );
        }

        if (report.mediumCount >= 5) {
            result.behaviors.add(
                    "Accumulation of medium-risk patterns detected"
            );
        }

        if (!report.urlsFound.isEmpty()) {
            result.behaviors.add(
                    "Unencrypted HTTP communication detected ("
                            + report.urlsFound.size() + " URL(s))"
            );
            result.threats.add(
                    "Cleartext traffic exposes data to interception"
            );
        }

        if (!report.hardcodedSecrets.isEmpty()) {
            result.behaviors.add(
                    "Hardcoded secrets found in binary ("
                            + report.hardcodedSecrets.size() + " secret(s))"
            );
            result.threats.add(
                    "Exposed credentials may allow backend access"
            );
        }

        if (!report.nativeLibraries.isEmpty()) {
            result.behaviors.add(
                    "Native libraries detected ("
                            + report.nativeLibraries.size() + " .so) — static analysis limited"
            );
        }

        // SDK trop ancien
        if (report.minSdk > 0 && report.minSdk < 21) {

            score += 10;

            result.behaviors.add(
                    "Outdated Android SDK detected"
            );
        }

        // ============================================
        // NORMALISATION
        // ============================================

        if (score > 100)
            score = 100;

        result.riskScore = score;

        // ============================================
        // VERDICT FINAL
        // ============================================

        if (score >= 80) {

            result.verdict = "MALWARE";

        } else if (score >= 50) {

            result.verdict = "HIGH_RISK";

        } else if (score >= 25) {

            result.verdict = "SUSPICIOUS";

        } else {

            result.verdict = "SAFE";
        }

        // ============================================
        // CAS SAFE
        // ============================================

        if (result.behaviors.isEmpty()) {
            result.behaviors.add("No malicious behavior pattern detected");
            result.behaviors.add("App appears to follow standard security practices");
        }

        return result;
    }
}