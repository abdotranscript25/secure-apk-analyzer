package com.secure.analyzer.classifiers;

import com.secure.analyzer.analyzers.UltimateAnalyzer.UltimateReport;
import com.secure.analyzer.models.SecurityFinding;
import com.secure.analyzer.models.Severity;

import java.util.*;

/**
 * RiskPredictor — Module IA de prédiction de risque
 * Basé sur un système de scoring pondéré (inspiré Naive Bayes)
 */
public class RiskPredictor {

    // ============================================
    // RÉSULTAT DE LA PRÉDICTION
    // ============================================
    public static class PredictionResult {
        public String riskCategory;      // MALWARE, HIGH_RISK, SUSPICIOUS, SAFE
        public double confidenceScore;   // 0.0 à 1.0
        public int aiScore;              // 0 à 100
        public String verdict;           // Verdict final
        public List<String> reasons;     // Explications
        public List<String> recommendations; // Recommandations

        public PredictionResult() {
            reasons = new ArrayList<>();
            recommendations = new ArrayList<>();
        }
    }

    // ============================================
    // POIDS DES FEATURES (inspiré Naive Bayes)
    // ============================================
    private static final Map<String, Double> FEATURE_WEIGHTS = new LinkedHashMap<>();

    static {
        // Permissions dangereuses
        FEATURE_WEIGHTS.put("READ_SMS",                    0.90);
        FEATURE_WEIGHTS.put("SEND_SMS",                    0.85);
        FEATURE_WEIGHTS.put("PROCESS_OUTGOING_CALLS",      0.88);
        FEATURE_WEIGHTS.put("BIND_ACCESSIBILITY_SERVICE",  0.95);
        FEATURE_WEIGHTS.put("ACCESS_FINE_LOCATION",        0.60);
        FEATURE_WEIGHTS.put("READ_CONTACTS",               0.55);
        FEATURE_WEIGHTS.put("RECORD_AUDIO",                0.70);
        FEATURE_WEIGHTS.put("CAMERA",                      0.50);
        FEATURE_WEIGHTS.put("REQUEST_INSTALL_PACKAGES",    0.75);

        // Vulnérabilités code
        FEATURE_WEIGHTS.put("SQL_INJECTION",               0.92);
        FEATURE_WEIGHTS.put("WEBVIEW_INTERFACE",           0.85);
        FEATURE_WEIGHTS.put("ALLOW_ALL_HOSTNAME_VERIFIER", 0.90);
        FEATURE_WEIGHTS.put("DEBUGGABLE",                  0.80);
        FEATURE_WEIGHTS.put("HARDCODED_SECRET",            0.88);
        FEATURE_WEIGHTS.put("JWT_TOKEN",                   0.85);
        FEATURE_WEIGHTS.put("WEAK_CRYPTO",                 0.60);
        FEATURE_WEIGHTS.put("SENSITIVE_LOG",               0.55);
        FEATURE_WEIGHTS.put("HTTP_URL",                    0.50);
        FEATURE_WEIGHTS.put("CLEARTEXT_TRAFFIC",           0.65);
        FEATURE_WEIGHTS.put("ALLOW_BACKUP",                0.45);
    }

    // ============================================
    // MÉTHODE PRINCIPALE
    // ============================================
    public static PredictionResult predict(UltimateReport report) {
        PredictionResult result = new PredictionResult();

        // 1. Extraire les features
        Map<String, Double> features = extractFeatures(report);

        // 2. Calculer le score IA
        double rawScore = calculateScore(features, report);

        // 3. Normaliser le score (0-100)
        result.aiScore = (int) Math.min(100, Math.max(0, rawScore));

        // 4. Déterminer la catégorie
        result.riskCategory = categorize(result.aiScore, report);

        // 5. Calculer la confiance
        result.confidenceScore = calculateConfidence(report);

        // 6. Générer le verdict
        result.verdict = generateVerdict(result);

        // 7. Générer les explications
        result.reasons = generateReasons(features, report);

        // 8. Générer les recommandations
        result.recommendations = generateRecommendations(result.riskCategory, report);

        return result;
    }

    // ============================================
    // EXTRACTION DES FEATURES
    // ============================================
    private static Map<String, Double> extractFeatures(UltimateReport report) {
        Map<String, Double> features = new LinkedHashMap<>();

        // Features basées sur les permissions
        for (String perm : report.dangerousPermissions) {
            for (String key : FEATURE_WEIGHTS.keySet()) {
                if (perm.contains(key)) {
                    features.put(key, FEATURE_WEIGHTS.get(key));
                }
            }
        }

        // Features basées sur les findings
        for (SecurityFinding f : report.getAllFindings()) {
            for (String label : f.getSensitiveLabels()) {
                if (FEATURE_WEIGHTS.containsKey(label)) {
                    features.put(label, FEATURE_WEIGHTS.get(label));
                }
            }
        }

        // Features basées sur les secrets
        if (!report.hardcodedSecrets.isEmpty()) {
            features.put("HARDCODED_SECRET", 0.88);
        }

        // Features basées sur les URLs HTTP
        if (report.urlsFound.stream().anyMatch(u -> u.startsWith("http://"))) {
            features.put("HTTP_URL", 0.50);
        }

        return features;
    }

    // ============================================
    // CALCUL DU SCORE
    // ============================================
    private static double calculateScore(Map<String, Double> features, UltimateReport report) {
        double score = 0.0;

        // Score basé sur les features pondérées
        for (double weight : features.values()) {
            score += weight * 20;
        }

        // Bonus selon sévérité
        score += report.criticalCount * 15;
        score += report.highCount * 8;
        score += report.mediumCount * 3;
        score += report.lowCount * 1;

        // Malus si minSdk trop ancien
        if (report.minSdk > 0 && report.minSdk < 21) {
            score += 15;
        }

        return score;
    }

    // ============================================
    // CATÉGORISATION
    // ============================================
    private static String categorize(int aiScore, UltimateReport report) {
        // Vérifier les indicateurs de malware
        boolean hasMalwareIndicators =
                report.dangerousPermissions.stream()
                        .anyMatch(p -> p.contains("BIND_ACCESSIBILITY_SERVICE")
                                || p.contains("READ_SMS")
                                || p.contains("PROCESS_OUTGOING_CALLS"))
                        && report.criticalCount > 2;

        if (hasMalwareIndicators || aiScore >= 80) return "MALWARE";
        if (aiScore >= 55) return "HIGH_RISK";
        if (aiScore >= 30) return "SUSPICIOUS";
        return "SAFE";
    }

    // ============================================
    // CONFIANCE
    // ============================================
    private static double calculateConfidence(UltimateReport report) {
        // Plus on a de findings, plus on est confiant
        int totalFindings = report.totalFindings;
        if (totalFindings == 0) return 0.50;
        if (totalFindings < 3) return 0.65;
        if (totalFindings < 7) return 0.78;
        if (totalFindings < 15) return 0.88;
        return 0.95;
    }

    // ============================================
    // VERDICT
    // ============================================
    private static String generateVerdict(PredictionResult result) {
        String confidence = String.format("%.0f%%", result.confidenceScore * 100);
        switch (result.riskCategory) {
            case "MALWARE":
                return "⚠️ Application potentiellement malveillante (confiance: " + confidence + ")";
            case "HIGH_RISK":
                return "🔴 Application à haut risque (confiance: " + confidence + ")";
            case "SUSPICIOUS":
                return "🟡 Application suspecte (confiance: " + confidence + ")";
            default:
                return "✅ Application relativement sûre (confiance: " + confidence + ")";
        }
    }

    // ============================================
    // EXPLICATIONS
    // ============================================
    private static List<String> generateReasons(
            Map<String, Double> features, UltimateReport report) {
        List<String> reasons = new ArrayList<>();

        if (features.containsKey("READ_SMS") || features.containsKey("SEND_SMS"))
            reasons.add("Accès aux SMS détecté — comportement typique de spyware");
        if (features.containsKey("BIND_ACCESSIBILITY_SERVICE"))
            reasons.add("Service d'accessibilité utilisé — risque élevé de keylogger");
        if (features.containsKey("SQL_INJECTION"))
            reasons.add("Injection SQL détectée dans le code");
        if (features.containsKey("HARDCODED_SECRET"))
            reasons.add("Secrets/clés API codés en dur dans l'application");
        if (features.containsKey("JWT_TOKEN"))
            reasons.add("Token JWT exposé dans le code source");
        if (features.containsKey("ALLOW_ALL_HOSTNAME_VERIFIER"))
            reasons.add("Validation SSL désactivée — vulnérable aux attaques MITM");
        if (features.containsKey("DEBUGGABLE"))
            reasons.add("Application debuggable en production");
        if (features.containsKey("HTTP_URL"))
            reasons.add("Communications non chiffrées (HTTP) détectées");
        if (features.containsKey("WEAK_CRYPTO"))
            reasons.add("Algorithmes cryptographiques obsolètes (MD5, SHA-1)");
        if (report.criticalCount > 3)
            reasons.add(report.criticalCount + " vulnérabilités critiques détectées");

        if (reasons.isEmpty())
            reasons.add("Aucun indicateur de risque majeur détecté");

        return reasons;
    }

    // ============================================
    // RECOMMANDATIONS
    // ============================================
    private static List<String> generateRecommendations(
            String category, UltimateReport report) {
        List<String> recs = new ArrayList<>();

        switch (category) {
            case "MALWARE":
                recs.add("🚫 Ne pas installer cette application");
                recs.add("📱 Signaler à Google Play Protect");
                recs.add("🔍 Audit de sécurité complet requis");
                break;
            case "HIGH_RISK":
                recs.add("⚠️ Réviser les permissions demandées");
                recs.add("🔐 Corriger les vulnérabilités critiques avant publication");
                recs.add("🧪 Tests de pénétration recommandés");
                break;
            case "SUSPICIOUS":
                recs.add("🔍 Analyser les permissions en détail");
                recs.add("🔒 Améliorer la configuration SSL/TLS");
                recs.add("📝 Revoir les pratiques de stockage de données");
                break;
            default:
                recs.add("✅ Continuer les bonnes pratiques de sécurité");
                recs.add("🔄 Mettre à jour les dépendances régulièrement");
                recs.add("📊 Effectuer des audits périodiques");
        }

        return recs;
    }
}