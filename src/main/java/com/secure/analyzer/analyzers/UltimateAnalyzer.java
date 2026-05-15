package com.secure.analyzer.analyzers;

import com.secure.analyzer.models.SecurityFinding;
import com.secure.analyzer.models.Severity;
import com.secure.analyzer.models.FindingType;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * UltimateAnalyzer v3.0 — APK Security Analyzer (MobSF-inspired)
 *
 * Améliorations vs v2.0 :
 *  - Passage unique sur les fichiers Java (plus 5x la même collecte)
 *  - Déduplication globale par empreinte (fichier + pattern + valeur)
 *  - Couverture étendue : network_security_config, strings.xml, libs .so
 *  - Manifest : composants exportés, taskAffinity, intent-filters, minSdk
 *  - Patterns enrichis : AWS/GCP/Firebase keys, PEM, JWT, Bearer tokens
 *  - Contexte ligne fourni dans chaque Finding (plus facile à trier)
 *  - Sévérités calibrées (évite les faux positifs sur HttpURLConnection, etc.)
 */
public class UltimateAnalyzer {

    // ============================================
    // CONSTANTES
    // ============================================

    private static final int MIN_RECOMMENDED_SDK = 29;
    /** Adapter selon votre environnement / OS */
    private static final String JADX_PATH = System.getProperty("jadx.path",
            System.getProperty("os.name").toLowerCase().contains("win")
                    ? "C:\\jadx-stable\\bin\\jadx.bat"
                    : "/usr/local/bin/jadx");

    // Taille max d'un fichier analysé (évite les OOM sur les gros .dex)
    private static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 Mo

    // -------- PERMISSIONS --------
    private static final Map<String, PermDef> DANGEROUS_PERMISSIONS = new LinkedHashMap<>();

    // -------- SECRETS EN DUR --------
    private static final List<SecretPattern> SECRET_PATTERNS = new ArrayList<>();

    // -------- CODE DANGEREUX (pattern → (description, sévérité)) --------
    private static final List<CodeRule> CODE_RULES = new ArrayList<>();

    // -------- AUTRES PATTERNS --------
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}");
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,6}");
    private static final Pattern IP_PRIVATE_PATTERN = Pattern.compile(
            "\\b(10\\.[0-9]{1,3}|172\\.(1[6-9]|2[0-9]|3[01])|192\\.168)\\.[0-9]{1,3}\\.[0-9]{1,3}\\b");
    private static final Pattern HTTP_URL_PATTERN = Pattern.compile(
            "http://(?!schemas\\.android\\.com|www\\.w3\\.org|apache\\.org|localhost|127\\.0\\.0\\.1)[a-zA-Z0-9.\\-/_%?&=+#]+");
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
            "(rawQuery|execSQL)\\s*\\(\\s*[^,)]*\\+[^,)]*[,)]",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern WEBVIEW_JS_PATTERN = Pattern.compile(
            "setJavaScriptEnabled\\s*\\(\\s*true\\s*\\)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern WEBVIEW_INTERFACE_PATTERN = Pattern.compile(
            "addJavascriptInterface\\s*\\(",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SENSITIVE_LOG_PATTERN = Pattern.compile(
            "Log\\.[vdiwef]\\s*\\([^)]*?(password|passwd|pwd|token|secret|auth|api[_\\-]?key|credential)[^)]*\\)",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern WEAK_CRYPTO_PATTERN = Pattern.compile(
            "\"(MD5|SHA-1|DES|RC4|ECB)\"",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern RANDOM_PATTERN = Pattern.compile(
            "new\\s+Random\\s*\\(\\s*\\)");
    private static final Pattern BEARER_TOKEN_PATTERN = Pattern.compile(
            "Bearer\\s+[A-Za-z0-9\\-._~+/]{20,}",
            Pattern.CASE_INSENSITIVE);

    // ============================================
    //  INITIALISATIONS STATIQUES
    // ============================================
    static {

        // --- Permissions dangereuses ---
        DANGEROUS_PERMISSIONS.put("CAMERA",                    new PermDef("Accès caméra",                  Severity.MEDIUM));
        DANGEROUS_PERMISSIONS.put("RECORD_AUDIO",              new PermDef("Enregistrement audio",           Severity.MEDIUM));
        DANGEROUS_PERMISSIONS.put("READ_CONTACTS",             new PermDef("Lecture contacts",               Severity.MEDIUM));
        DANGEROUS_PERMISSIONS.put("WRITE_CONTACTS",            new PermDef("Écriture contacts",              Severity.MEDIUM));
        DANGEROUS_PERMISSIONS.put("ACCESS_FINE_LOCATION",      new PermDef("Localisation GPS précise",       Severity.HIGH));
        DANGEROUS_PERMISSIONS.put("ACCESS_BACKGROUND_LOCATION",new PermDef("Localisation en arrière-plan",   Severity.HIGH));
        DANGEROUS_PERMISSIONS.put("READ_SMS",                  new PermDef("Lecture SMS",                    Severity.CRITICAL));
        DANGEROUS_PERMISSIONS.put("SEND_SMS",                  new PermDef("Envoi SMS",                      Severity.CRITICAL));
        DANGEROUS_PERMISSIONS.put("RECEIVE_SMS",               new PermDef("Réception SMS",                  Severity.HIGH));
        DANGEROUS_PERMISSIONS.put("READ_PHONE_STATE",          new PermDef("État téléphone / IMEI",          Severity.HIGH));
        DANGEROUS_PERMISSIONS.put("CALL_PHONE",                new PermDef("Appels téléphoniques",           Severity.HIGH));
        DANGEROUS_PERMISSIONS.put("READ_CALL_LOG",             new PermDef("Journal d'appels",               Severity.HIGH));
        DANGEROUS_PERMISSIONS.put("READ_EXTERNAL_STORAGE",     new PermDef("Lecture stockage externe",       Severity.MEDIUM));
        DANGEROUS_PERMISSIONS.put("WRITE_EXTERNAL_STORAGE",    new PermDef("Écriture stockage externe",      Severity.MEDIUM));
        DANGEROUS_PERMISSIONS.put("GET_ACCOUNTS",              new PermDef("Liste des comptes utilisateur",  Severity.MEDIUM));
        DANGEROUS_PERMISSIONS.put("USE_BIOMETRIC",             new PermDef("Données biométriques",           Severity.MEDIUM));
        DANGEROUS_PERMISSIONS.put("PROCESS_OUTGOING_CALLS",    new PermDef("Interception appels sortants",   Severity.CRITICAL));
        DANGEROUS_PERMISSIONS.put("BIND_ACCESSIBILITY_SERVICE",new PermDef("Service accessibilité (spyware)",Severity.CRITICAL));
        DANGEROUS_PERMISSIONS.put("SYSTEM_ALERT_WINDOW",       new PermDef("Overlay système (tapjacking)",   Severity.HIGH));
        DANGEROUS_PERMISSIONS.put("PACKAGE_USAGE_STATS",       new PermDef("Statistiques d'utilisation",     Severity.MEDIUM));
        DANGEROUS_PERMISSIONS.put("REQUEST_INSTALL_PACKAGES",  new PermDef("Installation de paquets",        Severity.HIGH));
        DANGEROUS_PERMISSIONS.put("READ_PRIVILEGED_PHONE_STATE",new PermDef("État téléphone privilégié",     Severity.CRITICAL));

        // --- Patterns secrets en dur ---
        // Format : (pattern-regex, groupIndex pour la valeur, label, sévérité)
        SECRET_PATTERNS.add(new SecretPattern(
                "(?i)(password|passwd|pwd)\\s*[=:]\\s*\"([^\"]{4,})\"", 2, "Mot de passe en dur", Severity.CRITICAL));
        SECRET_PATTERNS.add(new SecretPattern(
                "(?i)(secret|api[_\\-]?key|apikey|access[_\\-]?key|auth[_\\-]?token|client[_\\-]?secret)\\s*[=:]\\s*\"([^\"]{6,})\"", 2, "Clé/secret API en dur", Severity.CRITICAL));
        SECRET_PATTERNS.add(new SecretPattern(
                "(?i)(token)\\s*[=:]\\s*\"([A-Za-z0-9\\-._~+/]{16,})\"", 2, "Token en dur", Severity.HIGH));
        // AWS
        SECRET_PATTERNS.add(new SecretPattern(
                "AKIA[0-9A-Z]{16}", 0, "Clé AWS Access Key", Severity.CRITICAL));
        SECRET_PATTERNS.add(new SecretPattern(
                "(?i)aws[_\\-]?secret\\s*[=:]\\s*\"([^\"]{20,})\"", 1, "AWS Secret Key", Severity.CRITICAL));
        // Google / Firebase
        SECRET_PATTERNS.add(new SecretPattern(
                "AIza[0-9A-Za-z\\-_]{35}", 0, "Google API Key", Severity.CRITICAL));
        SECRET_PATTERNS.add(new SecretPattern(
                "(?i)firebase[_\\-]?api[_\\-]?key\\s*[=:]\\s*\"([^\"]+)\"", 1, "Firebase API Key", Severity.CRITICAL));
        // Private keys PEM
        SECRET_PATTERNS.add(new SecretPattern(
                "-----BEGIN (RSA |EC )?PRIVATE KEY-----", 0, "Clé privée PEM embarquée", Severity.CRITICAL));
        // Stripe
        SECRET_PATTERNS.add(new SecretPattern(
                "sk_(live|test)_[0-9a-zA-Z]{24,}", 0, "Stripe Secret Key", Severity.CRITICAL));
        // GitHub PAT
        SECRET_PATTERNS.add(new SecretPattern(
                "ghp_[A-Za-z0-9]{36}", 0, "GitHub Personal Access Token", Severity.CRITICAL));
        // Base64 long (possible secret encodé)
        SECRET_PATTERNS.add(new SecretPattern(
                "(?i)(private|secret|key|password)\\s*=\\s*\"([A-Za-z0-9+/]{32,}={0,2})\"", 2, "Valeur encodée Base64 suspecte", Severity.HIGH));

        // --- Règles de code dangereux ---
        CODE_RULES.add(new CodeRule("Runtime\\.getRuntime\\(\\)\\.exec\\(",                                "Exécution commande système",               Severity.HIGH));
        CODE_RULES.add(new CodeRule("new\\s+ProcessBuilder\\s*\\(",                                        "Création de processus externe",            Severity.HIGH));
        CODE_RULES.add(new CodeRule("System\\.loadLibrary\\(",                                             "Chargement bibliothèque native",           Severity.MEDIUM));
        CODE_RULES.add(new CodeRule("DexClassLoader|PathClassLoader",                                      "Chargement de code dynamique (DEX)",       Severity.HIGH));
        CODE_RULES.add(new CodeRule("setHostnameVerifier\\s*\\(",                                          "HostnameVerifier personnalisé (MITM)",     Severity.HIGH));
        CODE_RULES.add(new CodeRule("ALLOW_ALL_HOSTNAME_VERIFIER",                                         "Accepte tous les hostnames SSL",           Severity.CRITICAL));
        CODE_RULES.add(new CodeRule("(?i)class\\s+\\w+\\s+implements\\s+X509TrustManager",                "TrustManager personnalisé (MITM)",         Severity.CRITICAL));
        CODE_RULES.add(new CodeRule("checkClientTrusted|checkServerTrusted",                               "Validation certificat désactivée",         Severity.CRITICAL));
        CODE_RULES.add(new CodeRule("SSLContext\\.getInstance\\(\"SSL\"\\)",                               "Protocole SSL obsolète",                   Severity.HIGH));
        CODE_RULES.add(new CodeRule("setWebContentsDebuggingEnabled\\s*\\(\\s*true",                       "WebView debugging activé",                 Severity.HIGH));
        CODE_RULES.add(new CodeRule("setAllowFileAccess\\s*\\(\\s*true",                                   "WebView accès fichiers locaux",            Severity.HIGH));
        CODE_RULES.add(new CodeRule("setAllowUniversalAccessFromFileURLs\\s*\\(\\s*true",                  "WebView accès universel depuis file://",   Severity.CRITICAL));
        CODE_RULES.add(new CodeRule("MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE",                            "Fichier monde-lisible (fuite de données)", Severity.HIGH));
        CODE_RULES.add(new CodeRule("getSharedPreferences[^;]*MODE_WORLD",                                 "SharedPreferences accessible globalement", Severity.HIGH));
        CODE_RULES.add(new CodeRule("openFileOutput[^;]*MODE_WORLD",                                       "Fichier interne accessible globalement",   Severity.HIGH));
        CODE_RULES.add(new CodeRule("Cipher\\.getInstance\\(\"[^/]+/ECB",                                 "Chiffrement ECB (non sécurisé)",           Severity.HIGH));
        CODE_RULES.add(new CodeRule("MessageDigest\\.getInstance\\(\"MD5\"\\)",                            "Hash MD5 (cassé)",                         Severity.MEDIUM));
        CODE_RULES.add(new CodeRule("MessageDigest\\.getInstance\\(\"SHA-1\"\\)",                          "Hash SHA-1 (obsolète)",                    Severity.MEDIUM));
        CODE_RULES.add(new CodeRule("IvParameterSpec\\(new byte\\[\\d+\\]\\)",                             "IV statique pour chiffrement",             Severity.HIGH));
        CODE_RULES.add(new CodeRule("SecretKeySpec\\([^,]+,\\s*\"AES\"\\)",                                "Clé AES construite manuellement",          Severity.MEDIUM));
        CODE_RULES.add(new CodeRule("Base64\\.decode[^;]*(password|secret|key|token)",                    "Décodage Base64 de valeur sensible",       Severity.MEDIUM));
        CODE_RULES.add(new CodeRule("ClipboardManager.*setPrimaryClip|copyToClipboard",                    "Copie données dans le presse-papiers",     Severity.MEDIUM));
        CODE_RULES.add(new CodeRule("android\\.os\\.Debug\\.isDebuggerConnected",                          "Détection debugger (anti-debug)",          Severity.LOW));
    }

    // ============================================
    // CLASSES INTERNES DE CONFIGURATION
    // ============================================

    private static class PermDef {
        final String description;
        final Severity severity;
        PermDef(String d, Severity s) { description = d; severity = s; }
    }

    private static class SecretPattern {
        final Pattern pattern;
        final int group;   // 0 = match complet, N = groupe capturant
        final String label;
        final Severity severity;
        SecretPattern(String regex, int group, String label, Severity severity) {
            this.pattern = Pattern.compile(regex, Pattern.MULTILINE);
            this.group = group;
            this.label = label;
            this.severity = severity;
        }
    }

    private static class CodeRule {
        final Pattern pattern;
        final String description;
        final Severity severity;
        CodeRule(String regex, String description, Severity severity) {
            this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            this.description = description;
            this.severity = severity;
        }
    }

    // ============================================
    // STRUCTURE DU RAPPORT
    // ============================================
    public static class UltimateReport implements Serializable {
        private static final long serialVersionUID = 2L;

        // --- Métadonnées ---
        public String fileName;
        public String packageName;
        public String versionName;
        public int versionCode;
        public int minSdk;
        public int targetSdk;
        public long fileSize;
        public int totalClasses;

        // --- Score ---
        public int securityScore;
        public String riskLevel;
        public String securityGrade;

        // --- Compteurs sévérité ---
        public int criticalCount, highCount, mediumCount, lowCount;

        // --- Données extraites ---
        public Set<String> permissions        = new LinkedHashSet<>();
        public Set<String> dangerousPermissions = new LinkedHashSet<>();
        public Set<String> urlsFound          = new LinkedHashSet<>();
        public Set<String> emailsFound        = new LinkedHashSet<>();
        public Set<String> ipAddresses        = new LinkedHashSet<>();
        public Set<String> hardcodedSecrets   = new LinkedHashSet<>();
        public Set<String> nativeLibraries    = new LinkedHashSet<>();

        // --- Findings par catégorie ---
        public List<SecurityFinding> manifestFindings    = new ArrayList<>();
        public List<SecurityFinding> permissionFindings  = new ArrayList<>();
        public List<SecurityFinding> codeFindings        = new ArrayList<>();
        public List<SecurityFinding> networkFindings     = new ArrayList<>();
        public List<SecurityFinding> cryptoFindings      = new ArrayList<>();
        public List<SecurityFinding> dataFindings        = new ArrayList<>();

        public int totalFindings;

        /** Clés d'empreinte pour déduplication globale */
        private final Set<String> fingerprintsSeen = new HashSet<>();

        /**
         * Tente d'ajouter un finding ; retourne false si déjà vu (dédupliqué).
         * L'empreinte combine : fichier (nom seul) + rule/evidence.
         */
        public boolean tryAdd(List<SecurityFinding> target, SecurityFinding f) {
            // On normalise le nom de fichier pour regrouper le même pattern
            // trouvé dans plusieurs classes d'un même package
            String key = String.join("|",
                    f.getFileName() == null ? "" : f.getFileName(),
                    f.getEvidence() == null ? "" : f.getEvidence().substring(0, Math.min(80, f.getEvidence().length())),
                    f.getSeverity().name());
            if (fingerprintsSeen.add(key)) {
                target.add(f);
                return true;
            }
            return false;
        }

        public void calculateScore() {
            List<SecurityFinding> all = getAllFindings();
            totalFindings = all.size();
            criticalCount = highCount = mediumCount = lowCount = 0;

            for (SecurityFinding f : all) {
                switch (f.getSeverity()) {
                    case CRITICAL: criticalCount++; break;
                    case HIGH:     highCount++;     break;
                    case MEDIUM:   mediumCount++;   break;
                    default:       lowCount++;      break;
                }
            }

            securityScore = 100
                    - criticalCount * 15
                    - highCount     * 8
                    - mediumCount   * 3
                    - lowCount;
            securityScore = Math.max(0, Math.min(100, securityScore));

            if      (securityScore >= 90) securityGrade = "A+";
            else if (securityScore >= 80) securityGrade = "A";
            else if (securityScore >= 70) securityGrade = "B";
            else if (securityScore >= 60) securityGrade = "C";
            else if (securityScore >= 50) securityGrade = "D";
            else                          securityGrade = "F";

            if      (criticalCount > 0)  riskLevel = "CRITICAL";
            else if (highCount     > 0)  riskLevel = "HIGH";
            else if (mediumCount   > 2)  riskLevel = "MEDIUM";
            else                         riskLevel = "LOW";
        }

        public List<SecurityFinding> getAllFindings() {
            List<SecurityFinding> all = new ArrayList<>();
            all.addAll(manifestFindings);
            all.addAll(permissionFindings);
            all.addAll(codeFindings);
            all.addAll(networkFindings);
            all.addAll(cryptoFindings);
            all.addAll(dataFindings);
            return all;
        }
    }

    // ============================================
    // ANALYSE PRINCIPALE
    // ============================================
    public static UltimateReport analyze(String apkPath) throws Exception {
        UltimateReport report = new UltimateReport();
        File apkFile = new File(apkPath);
        if (!apkFile.exists()) throw new FileNotFoundException("APK introuvable : " + apkPath);

        report.fileName = apkFile.getName();
        report.fileSize = apkFile.length();

        log("╔══════════════════════════════════════════╗");
        log("║   APK Security Analyzer v3.0 (MobSF++)  ║");
        log("╚══════════════════════════════════════════╝");
        log("📱 " + apkPath);

        // ── Étape 1 : Décompresser l'APK ──
        log("\n[1/5] Décompression de l'APK...");
        File tempDir = extractApk(apkPath);

        // ── Étape 2 : Décompiler avec JADX ──
        log("[2/5] Décompilation avec JADX...");
        File javaSourceDir = decompileWithJadx(apkPath);
        boolean hasJadx = javaSourceDir != null && javaSourceDir.exists()
                && countJavaFiles(javaSourceDir) > 0;
        if (hasJadx) {
            report.totalClasses = countJavaFiles(javaSourceDir);
            log("   ✅ " + report.totalClasses + " fichiers Java décompilés");
        } else {
            log("   ⚠️  JADX indisponible – analyse limitée aux ressources binaires");
        }

        // ── Étape 3 : Manifest ──
        log("[3/5] Analyse du AndroidManifest.xml...");
        analyzeManifest(new File(tempDir, "AndroidManifest.xml"), report);

        // ── Étape 4 : Ressources XML (network_security_config, strings.xml) ──
        log("[4/5] Analyse des ressources XML...");
        analyzeNetworkSecurityConfig(tempDir, report);
        analyzeStringsXml(tempDir, report);
        analyzeNativeLibraries(tempDir, report);

        // ── Étape 5 : Code Java (passage unique) ──
        if (hasJadx) {
            log("[5/5] Analyse du code Java (passage unique)...");
            analyzeAllJavaFiles(javaSourceDir, report);
        }

        // URLs dans les fichiers bruts de l'APK
        scanRawFilesForUrls(tempDir, report);

        // ── Nettoyage ──
        deleteDirectory(tempDir);
        if (javaSourceDir != null) deleteDirectory(javaSourceDir);

        // ── Score ──
        report.calculateScore();
        printSummary(report);

        return report;
    }

    // ============================================
    // DÉCOMPILATION JADX
    // ============================================
    private static File decompileWithJadx(String apkPath) {
        File jadxBin = new File(JADX_PATH);
        if (!jadxBin.exists()) {
            log("   ❌ JADX non trouvé : " + JADX_PATH);
            return null;
        }

        String outputDir = System.getProperty("java.io.tmpdir")
                + File.separator + "jadx_" + System.currentTimeMillis();

        try {
            ProcessBuilder pb = new ProcessBuilder(
                    JADX_PATH,
                    "-d", outputDir,
                    "--show-bad-code",
                    "--no-res",
                    "--deobf",
                    apkPath);
            pb.redirectErrorStream(true);
            Process proc = pb.start();

            // Consommer la sortie pour éviter le blocage du buffer
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(proc.getInputStream()))) {
                while (br.readLine() != null) { /* discard */ }
            }

            proc.waitFor(240, TimeUnit.SECONDS);

            File src = new File(outputDir, "sources");
            if (src.exists() && countJavaFiles(src) > 0) return src;
            // Parfois JADX met les sources directement dans le dossier output
            if (countJavaFiles(new File(outputDir)) > 0) return new File(outputDir);

        } catch (Exception e) {
            log("   JADX erreur : " + e.getMessage());
        }
        return null;
    }

    // ============================================
    // ANALYSE MANIFEST
    // ============================================
    private static void analyzeManifest(File manifestFile, UltimateReport report) {
        if (manifestFile == null || !manifestFile.exists()) {
            log("   ⚠️  AndroidManifest.xml non trouvé (APK peut-être obfusqué)");
            return;
        }

        String content = readFileSafe(manifestFile);
        if (content == null || content.isBlank()) return;

        // ---- Métadonnées ----
        report.packageName = extractFirst(content, "package=\"([^\"]+)\"");
        report.versionName = extractFirst(content, "android:versionName=\"([^\"]+)\"");
        report.versionCode = parseInt(extractFirst(content, "android:versionCode=\"(\\d+)\""));
        report.minSdk      = parseInt(extractFirst(content, "android:minSdkVersion=\"(\\d+)\""));
        report.targetSdk   = parseInt(extractFirst(content, "android:targetSdkVersion=\"(\\d+)\""));

        // ---- Permissions ----
        Pattern permPat = Pattern.compile("android:name=\"(android\\.permission\\.[^\"]+)\"");
        Matcher m = permPat.matcher(content);
        while (m.find()) {
            String perm = m.group(1);
            report.permissions.add(perm);
            for (Map.Entry<String, PermDef> e : DANGEROUS_PERMISSIONS.entrySet()) {
                if (perm.contains(e.getKey()) && report.dangerousPermissions.add(perm)) {
                    PermDef def = e.getValue();
                    report.tryAdd(report.permissionFindings, new SecurityFinding(
                            FindingType.DANGEROUS_PERMISSION, "AndroidManifest.xml",
                            Collections.singletonList("PERMISSION"),
                            perm, def.severity,
                            "Permission dangereuse : " + def.description));
                    break;
                }
            }
        }

        // ---- Flags manifest ----
        addManifestFlag(report, content,
                "android:allowBackup=\"true\"",
                "allowBackup activé — sauvegarde ADB possible",
                FindingType.BACKUP_CONFIGURATION, Severity.HIGH,
                "Définir android:allowBackup=\"false\"");

        // allowBackup absent = implicitement true sur SDK < 31
        if (!content.contains("allowBackup=") && report.targetSdk < 31) {
            report.tryAdd(report.manifestFindings, new SecurityFinding(
                    FindingType.BACKUP_CONFIGURATION, "AndroidManifest.xml",
                    Collections.singletonList("ALLOW_BACKUP_IMPLICIT"),
                    "allowBackup absent (SDK < 31 → true par défaut)",
                    Severity.MEDIUM, "Définir android:allowBackup=\"false\" explicitement"));
        }

        addManifestFlag(report, content,
                "android:debuggable=\"true\"",
                "Application debuggable en production",
                FindingType.DEBUGGABLE, Severity.CRITICAL,
                "Retirer android:debuggable ou le forcer à false");

        addManifestFlag(report, content,
                "android:usesCleartextTraffic=\"true\"",
                "Trafic HTTP en clair autorisé",
                FindingType.CLEARTEXT_TRAFFIC, Severity.HIGH,
                "Désactiver usesCleartextTraffic et utiliser networkSecurityConfig");

        addManifestFlag(report, content,
                "android:networkSecurityConfig",
                null, null, null, null); // Juste vérifier l'absence ci-dessous

        if (!content.contains("android:networkSecurityConfig")) {
            report.tryAdd(report.manifestFindings, new SecurityFinding(
                    FindingType.NETWORK_SECURITY, "AndroidManifest.xml",
                    Collections.singletonList("NO_NETWORK_SECURITY_CONFIG"),
                    "networkSecurityConfig absent",
                    Severity.MEDIUM,
                    "Ajouter un fichier res/xml/network_security_config.xml"));
        }

        // ---- SDK trop ancien ----
        if (report.minSdk > 0 && report.minSdk < MIN_RECOMMENDED_SDK) {
            report.tryAdd(report.manifestFindings, new SecurityFinding(
                    FindingType.OUTDATED_SDK, "AndroidManifest.xml",
                    Collections.singletonList("MIN_SDK"),
                    "minSdkVersion=" + report.minSdk,
                    Severity.HIGH, "Passer minSdkVersion à " + MIN_RECOMMENDED_SDK + " ou plus"));
        }

        // ---- Composants exportés sans permission ----
        analyzeExportedComponents(content, report);

        // ---- TaskAffinity hijacking ----
        if (content.contains("android:taskAffinity=\"\"") || content.contains("android:taskAffinity=")) {
            report.tryAdd(report.manifestFindings, new SecurityFinding(
                    FindingType.TASK_AFFINITY, "AndroidManifest.xml",
                    Collections.singletonList("TASK_AFFINITY"),
                    "taskAffinity personnalisé détecté",
                    Severity.MEDIUM, "Risque de StrandHogg / task hijacking"));
        }
    }

    /** Vérifie les Activity/Service/Receiver exportés sans protection par permission */
    private static void analyzeExportedComponents(String content, UltimateReport report) {
        String[] componentTypes = {"activity", "service", "receiver", "provider"};
        for (String type : componentTypes) {
            Pattern compPat = Pattern.compile(
                    "<" + type + "[^>]*android:exported=\"true\"[^>]*>",
                    Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
            Matcher m = compPat.matcher(content);
            while (m.find()) {
                String block = m.group();
                boolean hasPermission = block.contains("android:permission=");
                if (!hasPermission) {
                    String name = extractFirst(block, "android:name=\"([^\"]+)\"");
                    report.tryAdd(report.manifestFindings, new SecurityFinding(
                            FindingType.EXPORTED_COMPONENT, "AndroidManifest.xml",
                            Collections.singletonList("EXPORTED_" + type.toUpperCase()),
                            name != null ? name : type + " exporté sans permission",
                            "provider".equals(type) ? Severity.HIGH : Severity.MEDIUM,
                            type + " exporté sans android:permission → accessible par toute app"));
                }
            }
        }
    }

    private static void addManifestFlag(UltimateReport report, String content,
                                        String flag, String evidence,
                                        FindingType type, Severity sev, String recommendation) {
        if (type == null) return; // utilisé pour les checks d'absence, traités ailleurs
        if (content.contains(flag)) {
            report.tryAdd(report.manifestFindings, new SecurityFinding(
                    type, "AndroidManifest.xml",
                    Collections.singletonList(flag.replaceAll("[^A-Z_a-z0-9]", "_").toUpperCase()),
                    evidence, sev, recommendation));
        }
    }

    // ============================================
    // ANALYSE network_security_config.xml
    // ============================================
    private static void analyzeNetworkSecurityConfig(File tempDir, UltimateReport report) {
        // Le fichier peut se trouver à différents endroits après extraction
        List<String> paths = Arrays.asList(
                "res/xml/network_security_config.xml",
                "res/xml/network_config.xml",
                "res/xml/security_config.xml");

        for (String rel : paths) {
            File f = new File(tempDir, rel);
            if (!f.exists()) continue;
            String content = readFileSafe(f);
            if (content == null) continue;

            if (content.contains("cleartextTrafficPermitted=\"true\"")) {
                report.tryAdd(report.networkFindings, new SecurityFinding(
                        FindingType.CLEARTEXT_TRAFFIC, f.getName(),
                        Collections.singletonList("NSC_CLEARTEXT"),
                        "cleartextTrafficPermitted=\"true\"",
                        Severity.HIGH, "Désactiver le trafic en clair dans networkSecurityConfig"));
            }
            if (content.contains("<trust-anchors>") && content.contains("user")) {
                report.tryAdd(report.networkFindings, new SecurityFinding(
                        FindingType.NETWORK_SECURITY, f.getName(),
                        Collections.singletonList("USER_CA_TRUSTED"),
                        "CA utilisateur faisant partie des trust-anchors",
                        Severity.HIGH, "Ne faire confiance qu'aux CA système en production"));
            }
            if (content.contains("<debug-overrides>")) {
                report.tryAdd(report.networkFindings, new SecurityFinding(
                        FindingType.NETWORK_SECURITY, f.getName(),
                        Collections.singletonList("DEBUG_OVERRIDES"),
                        "debug-overrides présent dans networkSecurityConfig",
                        Severity.MEDIUM, "S'assurer que les debug-overrides ne passent pas en production"));
            }
        }
    }

    // ============================================
    // ANALYSE strings.xml
    // ============================================
    private static void analyzeStringsXml(File tempDir, UltimateReport report) {
        File stringsFile = new File(tempDir, "res/values/strings.xml");
        if (!stringsFile.exists()) return;

        String content = readFileSafe(stringsFile);
        if (content == null) return;

        // Chercher des valeurs de type clé/secret dans les entrées string
        Pattern entry = Pattern.compile(
                "<string\\s+name=\"([^\"]*(?:key|secret|token|password|api|auth)[^\"]*)\">([^<]{4,})</string>",
                Pattern.CASE_INSENSITIVE);
        Matcher m = entry.matcher(content);
        while (m.find()) {
            String name = m.group(1);
            String value = m.group(2).trim();
            if (report.hardcodedSecrets.add(value)) {
                report.tryAdd(report.dataFindings, new SecurityFinding(
                        FindingType.HARDCODED_SECRET, "strings.xml",
                        Collections.singletonList("STRINGS_XML_SECRET"),
                        name + "=" + truncate(value, 60),
                        Severity.HIGH, "Secret/clé détecté dans strings.xml"));
            }
        }
    }

    // ============================================
    // BIBLIOTHÈQUES NATIVES (.so)
    // ============================================
    private static void analyzeNativeLibraries(File tempDir, UltimateReport report) {
        File libDir = new File(tempDir, "lib");
        if (!libDir.exists()) return;

        collectAllFiles(libDir, new ArrayList<>()).stream()
                .filter(f -> f.getName().endsWith(".so"))
                .forEach(f -> {
                    report.nativeLibraries.add(f.getName());
                    // Scan rapide des chaînes ASCII dans le binaire
                    scanBinaryForStrings(f, report);
                });
    }

    /** Extrait les chaînes ASCII lisibles d'un fichier binaire .so */
    private static void scanBinaryForStrings(File soFile, UltimateReport report) {
        if (soFile.length() > MAX_FILE_SIZE) return;
        try (DataInputStream dis = new DataInputStream(new FileInputStream(soFile))) {
            byte[] data = dis.readAllBytes();
            StringBuilder sb = new StringBuilder();
            for (byte b : data) {
                if (b >= 0x20 && b < 0x7F) {
                    sb.append((char) b);
                } else if (sb.length() >= 6) {
                    String s = sb.toString();
                    checkStringForSecrets(s, soFile.getName(), report);
                    sb.setLength(0);
                } else {
                    sb.setLength(0);
                }
            }
        } catch (Exception ignored) {}
    }

    // ============================================
    // ANALYSE JAVA — PASSAGE UNIQUE
    // ============================================
    /**
     * Un seul parcours des fichiers Java : toutes les règles sont appliquées
     * dans la même boucle. Cela évite de relire N fois les mêmes fichiers.
     */
    private static void analyzeAllJavaFiles(File javaSourceDir, UltimateReport report) {
        List<File> files = collectJavaFiles(javaSourceDir);
        log("   🔍 " + files.size() + " fichiers — application de toutes les règles...");

        for (File file : files) {
            String content = readFileSafe(file);
            if (content == null || content.isBlank()) continue;

            String fname = file.getName();
            String[] lines = content.split("\n");

            // ---- Règles de code dangereux ----
            for (CodeRule rule : CODE_RULES) {
                Matcher m = rule.pattern.matcher(content);
                while (m.find()) {
                    int lineNum = getLineNumber(content, m.start());
                    String evidence = truncate(lines[Math.max(0, lineNum - 1)].trim(), 120);
                    // Filtrer les faux positifs évidents (commentaires)
                    if (evidence.startsWith("//") || evidence.startsWith("*")) continue;
                    report.tryAdd(report.codeFindings, new SecurityFinding(
                            FindingType.DANGEROUS_CODE, fname,
                            Collections.singletonList(rule.description.replaceAll("\\s+", "_").toUpperCase()),
                            evidence, rule.severity, rule.description));
                }
            }

            // ---- Secrets en dur ----
            for (SecretPattern sp : SECRET_PATTERNS) {
                Matcher m = sp.pattern.matcher(content);
                while (m.find()) {
                    String value = sp.group == 0 ? m.group() : m.group(Math.min(sp.group, m.groupCount()));
                    if (value == null || value.length() < 4) continue;
                    if (isWhitelisted(value)) continue;
                    if (report.hardcodedSecrets.add(value)) {
                        report.tryAdd(report.dataFindings, new SecurityFinding(
                                FindingType.HARDCODED_SECRET, fname,
                                Collections.singletonList("HARDCODED_SECRET"),
                                sp.label + ": " + truncate(value, 60),
                                sp.severity, "Stocker les secrets dans un gestionnaire sécurisé (KeyStore, vault)"));
                    }
                }
            }

            // ---- SQL Injection ----
            Matcher sqlM = SQL_INJECTION_PATTERN.matcher(content);
            while (sqlM.find()) {
                report.tryAdd(report.codeFindings, new SecurityFinding(
                        FindingType.SQL_INJECTION, fname,
                        Collections.singletonList("SQL_INJECTION"),
                        truncate(sqlM.group().trim(), 120),
                        Severity.CRITICAL, "SQL injection possible — utiliser des requêtes paramétrées (?)"));
            }

            // ---- WebView XSS / RCE ----
            Matcher wjsM = WEBVIEW_JS_PATTERN.matcher(content);
            while (wjsM.find()) {
                report.tryAdd(report.codeFindings, new SecurityFinding(
                        FindingType.WEBVIEW_VULNERABILITY, fname,
                        Collections.singletonList("WEBVIEW_JS_ENABLED"),
                        truncate(wjsM.group().trim(), 120),
                        Severity.HIGH, "JavaScript WebView activé — désactiver si non nécessaire"));
            }
            Matcher wifM = WEBVIEW_INTERFACE_PATTERN.matcher(content);
            while (wifM.find()) {
                report.tryAdd(report.codeFindings, new SecurityFinding(
                        FindingType.WEBVIEW_VULNERABILITY, fname,
                        Collections.singletonList("WEBVIEW_INTERFACE"),
                        truncate(wifM.group().trim(), 120),
                        Severity.CRITICAL, "addJavascriptInterface — RCE possible via XSS"));
            }

            // ---- Logs sensibles ----
            Matcher logM = SENSITIVE_LOG_PATTERN.matcher(content);
            while (logM.find()) {
                report.tryAdd(report.codeFindings, new SecurityFinding(
                        FindingType.SENSITIVE_LOG, fname,
                        Collections.singletonList("SENSITIVE_LOG"),
                        truncate(logM.group().trim(), 120),
                        Severity.MEDIUM, "Ne pas logger de données sensibles en production"));
            }

            // ---- Crypto faible ----
            Matcher cryptoM = WEAK_CRYPTO_PATTERN.matcher(content);
            while (cryptoM.find()) {
                report.tryAdd(report.cryptoFindings, new SecurityFinding(
                        FindingType.WEAK_CRYPTOGRAPHY, fname,
                        Collections.singletonList("WEAK_CRYPTO"),
                        cryptoM.group().trim(),
                        Severity.MEDIUM, "Algorithme cryptographique obsolète ou faible"));
            }
            Matcher randM = RANDOM_PATTERN.matcher(content);
            while (randM.find()) {
                report.tryAdd(report.cryptoFindings, new SecurityFinding(
                        FindingType.WEAK_CRYPTOGRAPHY, fname,
                        Collections.singletonList("INSECURE_RANDOM"),
                        "new Random() — utiliser SecureRandom pour la cryptographie",
                        Severity.MEDIUM, "Remplacer java.util.Random par java.security.SecureRandom"));
            }

            // ---- JWT tokens exposés ----
            Matcher jwtM = JWT_PATTERN.matcher(content);
            while (jwtM.find()) {
                String jwt = jwtM.group();
                if (report.hardcodedSecrets.add(jwt)) {
                    report.tryAdd(report.dataFindings, new SecurityFinding(
                            FindingType.HARDCODED_SECRET, fname,
                            Collections.singletonList("JWT_TOKEN"),
                            truncate(jwt, 60),
                            Severity.CRITICAL, "Token JWT en dur dans le code"));
                }
            }

            // ---- Bearer token ----
            Matcher bearerM = BEARER_TOKEN_PATTERN.matcher(content);
            while (bearerM.find()) {
                String token = bearerM.group();
                if (report.hardcodedSecrets.add(token)) {
                    report.tryAdd(report.dataFindings, new SecurityFinding(
                            FindingType.HARDCODED_SECRET, fname,
                            Collections.singletonList("BEARER_TOKEN"),
                            truncate(token, 60),
                            Severity.CRITICAL, "Token Bearer en dur dans le code"));
                }
            }

            // ---- Emails ----
            Matcher emailM = EMAIL_PATTERN.matcher(content);
            while (emailM.find()) {
                String email = emailM.group();
                if (isWhitelistedEmail(email)) continue;
                if (report.emailsFound.add(email)) {
                    report.tryAdd(report.dataFindings, new SecurityFinding(
                            FindingType.INFORMATION_DISCLOSURE, fname,
                            Collections.singletonList("EMAIL"),
                            email, Severity.LOW, "Adresse email exposée dans le code"));
                }
            }

            // ---- URLs HTTP ----
            Matcher httpM = HTTP_URL_PATTERN.matcher(content);
            while (httpM.find()) {
                String url = httpM.group();
                if (report.urlsFound.add(url)) {
                    report.tryAdd(report.networkFindings, new SecurityFinding(
                            FindingType.INSECURE_CONNECTION, fname,
                            Collections.singletonList("HTTP_URL"),
                            url, Severity.HIGH, "URL HTTP non chiffrée — utiliser HTTPS"));
                }
            }

            // ---- IP privées ----
            Matcher ipM = IP_PRIVATE_PATTERN.matcher(content);
            while (ipM.find()) {
                String ip = ipM.group();
                if (report.ipAddresses.add(ip)) {
                    report.tryAdd(report.networkFindings, new SecurityFinding(
                            FindingType.INFORMATION_DISCLOSURE, fname,
                            Collections.singletonList("INTERNAL_IP"),
                            ip, Severity.MEDIUM, "Adresse IP interne exposée dans le code"));
                }
            }
        }
    }

    // ============================================
    // SCAN DES FICHIERS BRUTS (APK extrait)
    // ============================================
    private static void scanRawFilesForUrls(File tempDir, UltimateReport report) {
        for (File file : collectAllFiles(tempDir, new ArrayList<>())) {
            if (file.length() > MAX_FILE_SIZE) continue;
            String name = file.getName().toLowerCase();
            // Analyser seulement les fichiers textuels
            if (!name.endsWith(".xml") && !name.endsWith(".json")
                    && !name.endsWith(".html") && !name.endsWith(".js")
                    && !name.endsWith(".properties") && !name.endsWith(".txt")) continue;

            String content = readFileSafe(file);
            if (content == null) continue;

            Matcher m = HTTP_URL_PATTERN.matcher(content);
            while (m.find()) {
                String url = m.group();
                if (report.urlsFound.add(url)) {
                    report.tryAdd(report.networkFindings, new SecurityFinding(
                            FindingType.INSECURE_CONNECTION, file.getName(),
                            Collections.singletonList("HTTP_URL_RAW"),
                            url, Severity.MEDIUM, "URL HTTP dans les ressources"));
                }
            }

            checkStringForSecrets(content, file.getName(), report);
        }
    }

    /** Vérifie une chaîne pour des secrets — utilisé aussi pour les .so */
    private static void checkStringForSecrets(String content, String source, UltimateReport report) {
        for (SecretPattern sp : SECRET_PATTERNS) {
            Matcher m = sp.pattern.matcher(content);
            while (m.find()) {
                String value = sp.group == 0 ? m.group() : m.group(Math.min(sp.group, m.groupCount()));
                if (value == null || value.length() < 6 || isWhitelisted(value)) continue;
                if (report.hardcodedSecrets.add(value)) {
                    report.tryAdd(report.dataFindings, new SecurityFinding(
                            FindingType.HARDCODED_SECRET, source,
                            Collections.singletonList("SECRET_IN_RESOURCE"),
                            sp.label + ": " + truncate(value, 60),
                            sp.severity, "Secret détecté dans les ressources"));
                }
            }
        }
    }

    // ============================================
    // UTILITAIRES
    // ============================================

    private static File extractApk(String apkPath) throws IOException {
        File tempDir = new File(System.getProperty("java.io.tmpdir"),
                "apk_" + System.currentTimeMillis());
        tempDir.mkdirs();

        try (ZipFile zip = new ZipFile(apkPath)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                File dest = new File(tempDir, entry.getName());

                // Protection zip-slip
                if (!dest.getCanonicalPath().startsWith(tempDir.getCanonicalPath())) continue;

                if (!entry.isDirectory()) {
                    dest.getParentFile().mkdirs();
                    try (InputStream is = zip.getInputStream(entry);
                         FileOutputStream fos = new FileOutputStream(dest)) {
                        is.transferTo(fos);
                    }
                }
            }
        }
        return tempDir;
    }

    private static List<File> collectJavaFiles(File dir) {
        List<File> result = new ArrayList<>();
        collectJavaFilesRec(dir, result);
        return result;
    }

    private static void collectJavaFilesRec(File dir, List<File> result) {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File f : files) {
            if (f.isDirectory()) collectJavaFilesRec(f, result);
            else if (f.getName().endsWith(".java")) result.add(f);
        }
    }

    private static List<File> collectAllFiles(File dir, List<File> result) {
        File[] files = dir.listFiles();
        if (files == null) return result;
        for (File f : files) {
            if (f.isDirectory()) collectAllFiles(f, result);
            else result.add(f);
        }
        return result;
    }

    private static int countJavaFiles(File dir) {
        int count = 0;
        File[] files = dir.listFiles();
        if (files == null) return 0;
        for (File f : files) {
            if (f.isDirectory()) count += countJavaFiles(f);
            else if (f.getName().endsWith(".java")) count++;
        }
        return count;
    }

    private static String readFileSafe(File file) {
        if (file.length() > MAX_FILE_SIZE) return null;
        try {
            return Files.readString(file.toPath(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Fallback ISO-8859-1 pour les fichiers avec encodage mixte
            try {
                return Files.readString(file.toPath(), StandardCharsets.ISO_8859_1);
            } catch (Exception ex) {
                return null;
            }
        }
    }

    private static String extractFirst(String content, String regex) {
        Matcher m = Pattern.compile(regex).matcher(content);
        return m.find() ? m.group(1) : null;
    }

    private static int parseInt(String s) {
        if (s == null) return 0;
        try { return Integer.parseInt(s); } catch (Exception e) { return 0; }
    }

    private static int getLineNumber(String content, int index) {
        int line = 1;
        for (int i = 0; i < index && i < content.length(); i++) {
            if (content.charAt(i) == '\n') line++;
        }
        return line;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    /** Valeurs à ignorer (faux positifs courants) */
    private static boolean isWhitelisted(String value) {
        if (value == null) return true;
        String v = value.toLowerCase().trim();
        return v.equals("true") || v.equals("false") || v.equals("null")
                || v.equals("empty") || v.equals("none") || v.equals("n/a")
                || v.equals("placeholder") || v.equals("your_key_here")
                || v.equals("changeme") || v.startsWith("//")
                || v.length() < 4;
    }

    private static boolean isWhitelistedEmail(String email) {
        return email.endsWith("@example.com") || email.endsWith("@test.com")
                || email.contains("@schemas.android.com")
                || email.contains("@googlegroups.com");
    }

    private static void deleteDirectory(File dir) {
        if (dir == null || !dir.exists()) return;
        File[] files = dir.listFiles();
        if (files != null) for (File f : files) {
            if (f.isDirectory()) deleteDirectory(f);
            else f.delete();
        }
        dir.delete();
    }

    private static void log(String msg) {
        System.out.println(msg);
    }

    private static void printSummary(UltimateReport r) {
        log("\n╔══════════════════════════════════╗");
        log("║         RÉSULTAT FINAL           ║");
        log("╠══════════════════════════════════╣");
        log(String.format("║  Package   : %-20s ║", truncate(r.packageName, 20)));
        log(String.format("║  Score     : %3d/100  Grade : %-4s ║", r.securityScore, r.securityGrade));
        log(String.format("║  Risque    : %-20s ║", r.riskLevel));
        log("╠══════════════════════════════════╣");
        log(String.format("║  🔴 CRITICAL : %-3d  🟠 HIGH : %-3d ║", r.criticalCount, r.highCount));
        log(String.format("║  🟡 MEDIUM  : %-3d  🟢 LOW  : %-3d ║", r.mediumCount,   r.lowCount));
        log(String.format("║  Total findings : %-14d ║", r.totalFindings));
        log("╚══════════════════════════════════╝\n");
    }
}