package com.secure.analyzer.engine;

/**
 * Analyse le contexte d'une classe Java pour déterminer ses capacités et son domaine.
 * Permet de filtrer les faux positifs en fonction de ce que la classe est censée faire.
 */
public class ClassContext {

    // === Catégories principales ===
    public final boolean usesWebView;
    public final boolean usesCrypto;
    public final boolean usesRandom;
    public final boolean usesNetwork;
    public final boolean usesSSL;
    public final boolean usesFileIO;
    public final boolean usesRuntimeExec;
    public final boolean usesBase64;
    public final boolean usesDatabase;
    public final boolean usesReflection;

    // === Catégories de classe ===
    public final boolean isActivity;
    public final boolean isService;
    public final boolean isFragment;
    public final boolean isApplication;
    public final boolean isView;
    public final boolean isTest;
    public final boolean isUiLayer;

    // === Niveau de confiance ===
    public final boolean isApplicationCode;
    public final boolean isSystemLibrary;
    public final String className;

    private ClassContext(String content, String className) {
        this.className = className;
        String c = content.toLowerCase();

        // === Détection des usages ===
        // WebView
        usesWebView = c.contains("webview") ||
                c.contains("addjavascriptinterface") ||
                c.contains("setjavascriptenabled") ||
                c.contains("loadurl(") ||
                c.contains("webchromeclient") ||
                c.contains("webviewclient");

        // Crypto
        usesCrypto = c.contains("cipher") ||
                c.contains("messagedigest") ||
                c.contains("secretkey") ||
                c.contains("ivparameterspec") ||
                c.contains("keystore") ||
                c.contains("privatekey") ||
                c.contains("publickey") ||
                c.contains("signature") ||
                c.contains("mac.");

        // Random
        usesRandom = c.contains("new random(") ||
                c.contains("math.random") ||
                c.contains("threadlocalrandom");

        // Network
        usesNetwork = c.contains("httpurlconnection") ||
                c.contains("okhttpclient") ||
                c.contains("retrofit") ||
                c.contains("url(") ||
                c.contains("socket") ||
                c.contains("serversocket") ||
                c.contains("websocket") ||
                c.contains("httpclient");

        // SSL / Certificats
        usesSSL = c.contains("trustmanager") ||
                c.contains("sslcontext") ||
                c.contains("checkservertrusted") ||
                c.contains("checkclienttrusted") ||
                c.contains("hostnameverifier") ||
                c.contains("x509");

        // File I/O
        usesFileIO = c.contains("fileoutputstream") ||
                c.contains("fileinputstream") ||
                c.contains("getfilesdir") ||
                c.contains("getexternalstoragedirectory") ||
                c.contains("openfileinput") ||
                c.contains("openfileoutput") ||
                c.contains("sharedpreferences") ||
                c.contains("contentvalues");

        // Runtime exec
        usesRuntimeExec = c.contains("runtime.getruntime().exec") ||
                c.contains("processbuilder") ||
                c.contains("runtime.exec");

        // Base64
        usesBase64 = c.contains("base64.decode") ||
                c.contains("base64.encode") ||
                c.contains("android.util.base64") ||
                c.contains("java.util.base64");

        // Database
        usesDatabase = c.contains("sqlitedatabase") ||
                c.contains("room.database") ||
                c.contains("rawquery") ||
                c.contains("execsql") ||
                c.contains("contentprovider");

        // Reflection
        usesReflection = c.contains("class.forname") ||
                c.contains("getdeclaredmethod") ||
                c.contains("getdeclaredfield") ||
                c.contains("method.invoke") ||
                c.contains("field.set");

        // === Catégories de classe ===
        isActivity = className != null &&
                (className.endsWith("Activity") || content.contains("extends AppCompatActivity"));
        isService = className != null && className.endsWith("Service");
        isFragment = className != null && (className.endsWith("Fragment") || content.contains("extends Fragment"));
        isApplication = className != null && className.endsWith("Application");
        isView = className != null && (className.endsWith("View") || className.endsWith("Layout"));
        isTest = className != null && (className.endsWith("Test") || c.contains("junit") || c.contains("mockito"));
        isUiLayer = isActivity || isFragment || isView;

        // === Niveau de confiance ===
        isSystemLibrary = c.contains("androidx.") ||
                c.contains("com.google.") ||
                c.contains("kotlin.") ||
                c.contains("org.apache.") ||
                c.contains("javax.");

        isApplicationCode = !isSystemLibrary &&
                !isTest &&
                !c.contains("generated") &&
                !c.contains(".r.");
    }

    private static String extractClassName(String content) {
        // Pattern pour trouver "public class NomClasse" ou "class NomClasse"
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                "(?:public\\s+)?(?:abstract\\s+)?(?:final\\s+)?(?:static\\s+)?class\\s+(\\w+)");
        java.util.regex.Matcher m = p.matcher(content);
        if (m.find()) {
            return m.group(1);
        }
        return "Unknown";
    }

    public static ClassContext from(String content) {
        String className = extractClassName(content);
        return new ClassContext(content, className);
    }

    /**
     * Vérifie si la classe a un contexte sécuritaire (crypto, réseau, authentification)
     */
    public boolean isSecureContext() {
        return usesCrypto || usesNetwork || usesSSL || usesDatabase;
    }

    /**
     * Vérifie si la classe est susceptible de contenir des vulnérabilités
     */
    public boolean isPotentialVulnerable() {
        return (usesWebView && (usesNetwork || usesFileIO)) ||
                (usesCrypto && usesRandom) ||
                (usesNetwork && usesRuntimeExec) ||
                (usesDatabase && (usesNetwork || usesFileIO));
    }

    /**
     * Retourne un résumé textuel du contexte
     */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("Class: ").append(className).append("\n");
        sb.append("  WebView: ").append(usesWebView).append("\n");
        sb.append("  Crypto: ").append(usesCrypto).append("\n");
        sb.append("  Network: ").append(usesNetwork).append("\n");
        sb.append("  Database: ").append(usesDatabase).append("\n");
        sb.append("  FileIO: ").append(usesFileIO).append("\n");
        sb.append("  RuntimeExec: ").append(usesRuntimeExec).append("\n");
        sb.append("  Activity: ").append(isActivity).append("\n");
        sb.append("  App Code: ").append(isApplicationCode).append("\n");
        return sb.toString();
    }
}