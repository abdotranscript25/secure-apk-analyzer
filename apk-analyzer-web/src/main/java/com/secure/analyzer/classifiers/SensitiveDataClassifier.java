package com.secure.analyzer.classifiers;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Classificateur de données sensibles basé sur des règles (regex + mots-clés)
 * Détecte: JWT tokens, emails, téléphones, données santé, cartes bancaires, etc.
 */
public class SensitiveDataClassifier {

    // Classe interne pour les résultats
    public static class ClassificationResult {
        private final List<String> labels;
        private final float confidence;

        public ClassificationResult(List<String> labels, float confidence) {
            this.labels = labels;
            this.confidence = confidence;
        }

        public List<String> getLabels() { return labels; }
        public float getConfidence() { return confidence; }
        public boolean hasLabels() { return !labels.isEmpty(); }
    }

    // Classe interne pour les règles de détection
    private static class DetectionRule {
        final String name;
        final Pattern pattern;
        final List<String> keywords;
        final float minConfidence;

        DetectionRule(String name, Pattern pattern, List<String> keywords, float minConfidence) {
            this.name = name;
            this.pattern = pattern;
            this.keywords = keywords;
            this.minConfidence = minConfidence;
        }

        DetectionRule(String name, Pattern pattern, float minConfidence) {
            this(name, pattern, new ArrayList<>(), minConfidence);
        }
    }

    // ============================================
    // LISTE COMPLÈTE DES RÈGLES DE DÉTECTION
    // ============================================
    private static final List<DetectionRule> RULES = Arrays.asList(

            // 1. JWT TOKEN (JSON Web Token)
            new DetectionRule(
                    "JWT_TOKEN",
                    Pattern.compile("eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*"),
                    0.95f
            ),

            // 2. EMAIL (courriels)
            new DetectionRule(
                    "EMAIL",
                    Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"),
                    Arrays.asList(
                            "email", "mail", "e-mail", "user_email", "account_email",
                            "contact_email", "primary_email", "secondary_email",
                            "courriel", "adresse_email", "email_utilisateur"
                    ),
                    0.95f
            ),

            // 3. PASSWORD (mots de passe - version complète)
            new DetectionRule(
                    "PASSWORD",
                    Pattern.compile(".*"),
                    Arrays.asList(
                            // Anglais - mots simples
                            "password", "pass", "pwd", "secret", "key",
                            // Anglais - composés
                            "user_password", "login_password", "old_password",
                            "new_password", "current_password", "confirm_password",
                            "password_hash", "password_salt", "encrypted_password",
                            // Tokens
                            "token", "access_token", "refresh_token", "auth_token",
                            "bearer_token", "jwt_token", "api_token", "session_token",
                            // Clés API
                            "api_key", "apikey", "api_secret", "client_secret",
                            "app_secret", "private_key", "public_key", "secret_key",
                            "consumer_key", "consumer_secret",
                            // Français
                            "motdepasse", "mot_de_passe", "mdp", "cle", "clef",
                            "code_secret", "token_acces",
                            // Espagnol
                            "contraseña", "clave",
                            // Portugais
                            "senha",
                            // Allemand
                            "passwort"
                    ),
                    0.75f
            ),

            // 4. HEALTH_DATA (données de santé - version complète)
            new DetectionRule(
                    "HEALTH_DATA",
                    Pattern.compile(".*"),
                    Arrays.asList(
                            // Signes vitaux (anglais)
                            "blood_pressure", "blood pressure", "heart_rate", "heart rate",
                            "temperature", "glucose", "oxygen", "saturation", "spo2",
                            // Signes vitaux (français)
                            "tension", "pression", "pouls", "frequence_cardique",
                            "glycemie", "oxygene", "saturation",
                            // Diagnostic
                            "diagnosis", "diagnostic", "condition", "pathologie",
                            "disease", "maladie", "symptom", "symptome",
                            // Traitement
                            "medication", "medicament", "prescription", "ordonnance",
                            "treatment", "traitement", "vaccination", "vaccin",
                            "allergy", "allergie", "intolerance",
                            // Patient
                            "patient", "patient_id", "medical_record", "dossier_medical",
                            "hospital", "hopital", "doctor", "medecin", "clinic", "clinique",
                            // Mesures corporelles
                            "poids", "weight", "taille", "height", "imc", "bmi",
                            "cholesterol", "cholesterole", "thyroid", "thyroide",
                            // Français spécifique
                            "cancer", "diabete", "diabetes", "asthme", "asthma",
                            "epilepsie", "epilepsy", "migraine"
                    ),
                    0.80f
            ),

            // 5. PHONE_NUMBER (numéros de téléphone - version complète)
            new DetectionRule(
                    "PHONE_NUMBER",
                    Pattern.compile("\\+[0-9]{1,3}[\\s.-]?[0-9]{2}[\\s.-]?[0-9]{2}[\\s.-]?[0-9]{2}[\\s.-]?[0-9]{2}"),
                    Arrays.asList(
                            "phone", "mobile", "cell", "telephone", "tel", "fax",
                            "work_phone", "home_phone", "emergency_phone",
                            "whatsapp", "contact_number", "phone_number",
                            "telephone", "portable", "fixe", "numéro", "numero"
                    ),
                    0.70f
            ),

            // 6. CREDIT_CARD (cartes bancaires)
            new DetectionRule(
                    "CREDIT_CARD",
                    Pattern.compile("\\b[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}[\\s-]?[0-9]{4}\\b"),
                    Arrays.asList(
                            "credit_card", "card_number", "cc_number", "pan",
                            "visa", "mastercard", "amex", "american_express",
                            "carte_bancaire", "numero_carte", "cb",
                            "expiry_date", "expiration", "cvv", "cvc", "cvv2"
                    ),
                    0.90f
            ),

            // 7. USER_ID (identifiants utilisateur)
            new DetectionRule(
                    "USER_ID",
                    Pattern.compile("[A-Z0-9]{8,20}"),
                    Arrays.asList(
                            "user_id", "userId", "uid", "uuid", "userid",
                            "national_id", "ssn", "cin", "nif", "passport",
                            "driver_license", "identity_card", "carte_identite",
                            "account_id", "profile_id", "customer_id", "client_id",
                            "employee_id", "student_id"
                    ),
                    0.65f
            ),

            // 8. GPS_COORDINATES (coordonnées GPS)
            new DetectionRule(
                    "GPS_COORDINATES",
                    Pattern.compile("-?\\d{1,3}\\.\\d+\\s*,\\s*-?\\d{1,3}\\.\\d+"),
                    Arrays.asList(
                            "latitude", "longitude", "lat", "lng", "gps",
                            "location", "position", "coordinate", "coord",
                            "coordonnees", "geolocalisation"
                    ),
                    0.85f
            ),

            // 9. URL (liens web)
            new DetectionRule(
                    "URL",
                    Pattern.compile("https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/[a-zA-Z0-9?=&._/-]*)?"),
                    Arrays.asList(
                            "url", "link", "href", "website", "site",
                            "redirect_uri", "callback_url", "webhook", "endpoint"
                    ),
                    0.80f
            ),

            // 10. BIRTH_DATE (dates de naissance)
            new DetectionRule(
                    "BIRTH_DATE",
                    Pattern.compile("\\d{2}/\\d{2}/\\d{4}|\\d{4}-\\d{2}-\\d{2}|\\d{2}-\\d{2}-\\d{4}"),
                    Arrays.asList(
                            "birth", "birthday", "birthdate", "dob", "date_of_birth",
                            "naissance", "date_naissance", "anniversaire",
                            "age", "born", "birth_year"
                    ),
                    0.75f
            ),

            // 11. BANK_ACCOUNT (comptes bancaires - IBAN/BIC)
            new DetectionRule(
                    "BANK_ACCOUNT",
                    Pattern.compile("[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}"),
                    Arrays.asList(
                            "iban", "bic", "swift", "bank_account", "account_number",
                            "rib", "compte_bancaire", "routing_number", "sort_code"
                    ),
                    0.85f
            ),

            // 12. API_KEY (clés d'API)
            new DetectionRule(
                    "API_KEY",
                    Pattern.compile("[a-zA-Z0-9_\\-]{20,}"),
                    Arrays.asList(
                            "api_key", "apikey", "api_secret", "api_secret_key",
                            "client_id", "client_secret", "app_secret", "app_key",
                            "access_key", "secret_key", "private_key", "public_key",
                            "consumer_key", "consumer_secret"
                    ),
                    0.80f
            ),

            // 13. IP_ADDRESS (adresses IP)
            new DetectionRule(
                    "IP_ADDRESS",
                    Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b"),
                    Arrays.asList(
                            "ip", "ip_address", "ipaddr", "host", "server_ip",
                            "adresse_ip", "ip_utilisateur"
                    ),
                    0.70f
            ),

            // 14. MAC_ADDRESS (adresses MAC)
            new DetectionRule(
                    "MAC_ADDRESS",
                    Pattern.compile("([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"),
                    Arrays.asList(
                            "mac", "mac_address", "wifi_mac", "bluetooth_mac",
                            "adresse_mac"
                    ),
                    0.85f
            ),

            // 15. SOCIAL_SECURITY (numéro de sécurité sociale)
            new DetectionRule(
                    "SOCIAL_SECURITY",
                    Pattern.compile("\\d{2}-\\d{6}-\\d{2}"),
                    Arrays.asList(
                            "ssn", "social_security", "socialsecurity",
                            "securite_sociale", "num_secu",
                            "cnss", "cnas", "numero_cnss", "immatriculation"
                    ),
                    0.90f
            )
    );

    // ============================================
    // MÉTHODES PRINCIPALES
    // ============================================

    /**
     * Classifie une chaîne de caractères
     */
    public static ClassificationResult classify(String input) {
        if (input == null || input.trim().isEmpty()) {
            return new ClassificationResult(new ArrayList<>(), 0f);
        }

        String trimmedInput = input.trim();
        Set<String> detectedLabels = new HashSet<>();
        float maxConfidence = 0f;

        for (DetectionRule rule : RULES) {
            float confidence = 0f;

            // Vérification avec regex
            Matcher matcher = rule.pattern.matcher(trimmedInput);
            if (matcher.find()) {
                String match = matcher.group();
                if (match.length() >= 5) {
                    float lengthFactor = Math.min(1.0f, match.length() / 20.0f);
                    confidence = Math.max(confidence, rule.minConfidence * (lengthFactor + 0.2f));
                }
            }

            // Vérification des mots-clés
            if (!rule.keywords.isEmpty()) {
                String inputLower = trimmedInput.toLowerCase();
                for (String keyword : rule.keywords) {
                    if (inputLower.contains(keyword.toLowerCase())) {
                        float keywordConfidence = rule.minConfidence + 0.15f;
                        confidence = Math.max(confidence, Math.min(0.95f, keywordConfidence));
                        break;
                    }
                }
            }

            // Ajouter si confiance suffisante
            if (confidence >= rule.minConfidence) {
                if (!isObviousFalsePositive(trimmedInput, rule.name)) {
                    detectedLabels.add(rule.name);
                    maxConfidence = Math.max(maxConfidence, confidence);
                }
            }
        }

        return new ClassificationResult(new ArrayList<>(detectedLabels), maxConfidence);
    }

    /**
     * Filtre les faux positifs évidents
     */
    private static boolean isObviousFalsePositive(String input, String label) {
        // Textes trop courts
        if (input.length() < 3) return true;

        // Mots communs non sensibles
        List<String> commonWords = Arrays.asList(
                "hello", "world", "test", "example", "foo", "bar",
                "lorem", "ipsum", "dolor", "sit", "amet", "the", "and"
        );

        if (commonWords.contains(input.toLowerCase())) {
            return true;
        }

        // Pour les emails, vérifier la présence de @
        if (label.equals("EMAIL") && !input.contains("@")) {
            return true;
        }

        // Pour les téléphones, minimum 8 chiffres
        if (label.equals("PHONE_NUMBER")) {
            int digitCount = 0;
            for (char c : input.toCharArray()) {
                if (Character.isDigit(c)) digitCount++;
            }
            if (digitCount < 8) return true;
        }

        // Pour les JWT, vérifier le format à 3 parties
        if (label.equals("JWT_TOKEN")) {
            String[] parts = input.split("\\.");
            if (parts.length != 3) return true;
            if (parts[0].length() < 10) return true;
        }

        // Pour les adresses IP, vérifier les valeurs
        if (label.equals("IP_ADDRESS")) {
            if (input.equals("0.0.0.0") || input.equals("127.0.0.1") || input.equals("255.255.255.255")) {
                return true;
            }
        }

        return false;
    }

    /**
     * Version simplifiée qui retourne seulement les labels
     */
    public static List<String> classifySimple(String input) {
        return classify(input).getLabels();
    }

    /**
     * Vérifie si la donnée est sensible
     */
    public static boolean isSensitive(String input) {
        return !classify(input).getLabels().isEmpty();
    }

    /**
     * Retourne le niveau de sévérité basé sur le type de donnée
     */
    public static String getSeverityForLabel(String label) {
        switch (label) {
            case "JWT_TOKEN":
            case "PASSWORD":
            case "CREDIT_CARD":
            case "SOCIAL_SECURITY":
                return "CRITICAL";
            case "HEALTH_DATA":
            case "API_KEY":
            case "BANK_ACCOUNT":
                return "CRITICAL";
            case "EMAIL":
            case "PHONE_NUMBER":
            case "GPS_COORDINATES":
            case "IP_ADDRESS":
            case "MAC_ADDRESS":
                return "HIGH";
            case "USER_ID":
            case "BIRTH_DATE":
                return "MEDIUM";
            case "URL":
                return "LOW";
            default:
                return "LOW";
        }
    }
    /**
     * Classifie uniquement via regex — sans mots-clés (pour les logs)
     */
    public static List<String> classifyByRegexOnly(String input) {
        if (input == null || input.trim().isEmpty()) return new ArrayList<>();

        List<String> labels = new ArrayList<>();

        // Garder SEULEMENT ces types stricts
        List<String> keepTypes = Arrays.asList(
                "JWT_TOKEN", "EMAIL", "CREDIT_CARD", "PHONE_NUMBER",
                "BANK_ACCOUNT", "SOCIAL_SECURITY"
        );

        for (DetectionRule rule : RULES) {
            if (!keepTypes.contains(rule.name)) continue;

            Matcher matcher = rule.pattern.matcher(input.trim());
            if (matcher.find()) {
                String match = matcher.group();
                if (match.length() >= 8) {
                    if (!isObviousFalsePositive(input.trim(), rule.name)) {
                        labels.add(rule.name);
                    }
                }
            }
        }
        return labels;
    }
}