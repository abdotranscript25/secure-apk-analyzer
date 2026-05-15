package com.secure.analyzer.analyzers;

import com.secure.analyzer.engine.ClassContext;
import java.util.List;

public class UsageContextAnalyzer {

    private final List<String> lines;
    private final ClassContext classContext;
    private final String content;

    public UsageContextAnalyzer(String content, ClassContext classContext) {
        this.content = content;
        this.classContext = classContext;
        this.lines = List.of(content.split("\n"));
    }

    // ============================================
    // MÉTHODE PRINCIPALE POUR LE FILTRAGE
    // ============================================

    /**
     * Détermine si un pattern trouvé représente un vrai problème de sécurité
     */
    public boolean isRealSecurityIssue(String match) {
        // 1. Ignorer les commentaires
        if (isInComment(match)) return false;

        // 2. Ignorer les imports et déclarations de package
        if (match.contains("import ") || match.contains("package ")) return false;

        // 3. Vérifier si c'est une déclaration (souvent sans danger)
        if (isDeclarationOnly(match)) return false;

        // 4. Vérifier si c'est réellement utilisé
        if (!isActuallyUsed(match)) return false;

        // 5. Contexte: si c'est une librairie système et que le code n'est pas critique
        if (isSystemLibrarySafe()) return false;

        return true;
    }

    // ============================================
    // MÉTHODES EXISTANTES (statiques)
    // ============================================

    public static boolean isRandomUsedForCrypto(List<String> lines, int index) {
        int start = Math.max(0, index - 8);
        int end = Math.min(lines.size(), index + 8);

        for (int i = start; i < end; i++) {
            String l = lines.get(i);

            if (l.contains("nextBytes") ||
                    l.contains("SecretKeySpec") ||
                    l.contains("IvParameterSpec") ||
                    l.contains("Cipher.init") ||
                    l.toLowerCase().contains("key") ||
                    l.toLowerCase().contains("token") ||
                    l.toLowerCase().contains("seed") ||
                    l.toLowerCase().contains("iv")) {
                return true;
            }
        }
        return false;
    }

    // Version d'instance pour Random
    public boolean isRandomUsedForCrypto(int lineIndex) {
        return isRandomUsedForCrypto(this.lines, lineIndex);
    }

    public static boolean isHttpUrlReallyUsed(List<String> lines, int index) {
        int start = Math.max(0, index - 6);
        int end = Math.min(lines.size(), index + 6);

        for (int i = start; i < end; i++) {
            String l = lines.get(i);

            if (l.contains("HttpURLConnection") ||
                    l.contains("OkHttpClient") ||
                    l.contains("Retrofit") ||
                    l.contains("openConnection") ||
                    l.contains("new URL(") ||
                    l.contains("Request.Builder")) {
                return true;
            }
        }
        return false;
    }

    // Version d'instance pour HttpUrl
    public boolean isHttpUrlReallyUsed(int lineIndex) {
        return isHttpUrlReallyUsed(this.lines, lineIndex);
    }

    public static boolean isBase64DecodingSecret(List<String> lines, int index) {
        int start = Math.max(0, index - 8);
        int end = Math.min(lines.size(), index + 8);

        for (int i = start; i < end; i++) {
            String l = lines.get(i).toLowerCase();

            if (l.contains("apikey") ||
                    l.contains("secret") ||
                    l.contains("token") ||
                    l.contains("password") ||
                    l.contains("auth") ||
                    l.contains("credential")) {
                return true;
            }
        }
        return false;
    }

    // Version d'instance pour Base64
    public boolean isBase64DecodingSecret(int lineIndex) {
        return isBase64DecodingSecret(this.lines, lineIndex);
    }

    public static boolean isWebViewLoadingExternalContent(List<String> lines, int index) {
        int start = Math.max(0, index - 10);
        int end = Math.min(lines.size(), index + 10);

        for (int i = start; i < end; i++) {
            String l = lines.get(i);

            if (l.contains("loadUrl(\"http") ||
                    l.contains("loadDataWithBaseURL") ||
                    l.contains("addJavascriptInterface") ||
                    l.contains("setJavaScriptEnabled(true)")) {
                return true;
            }
        }
        return false;
    }

    // Version d'instance pour WebView
    public boolean isWebViewLoadingExternalContent(int lineIndex) {
        return isWebViewLoadingExternalContent(this.lines, lineIndex);
    }

    // ============================================
    // MÉTHODES PRIVÉES POUR isRealSecurityIssue
    // ============================================

    private boolean isInComment(String match) {
        int index = content.indexOf(match);
        if (index < 0) return false;

        int lineStart = content.lastIndexOf('\n', index);
        if (lineStart < 0) lineStart = 0;
        String line = content.substring(lineStart, Math.min(content.length(), index + match.length()));

        return line.contains("//") || content.substring(Math.max(0, index - 2), index).equals("/*");
    }

    private boolean isDeclarationOnly(String match) {
        String[] declarationPatterns = {
                "new\\s+\\w+\\(", "=.*new\\s+", "\\w+\\s+\\w+\\s*=",
                "public\\s+\\w+\\(", "private\\s+\\w+\\(", "protected\\s+\\w+\\("
        };

        for (String pattern : declarationPatterns) {
            if (match.matches(".*" + pattern + ".*")) {
                return true;
            }
        }
        return false;
    }

    private boolean isActuallyUsed(String match) {
        // Chercher des patterns d'utilisation réelle
        String lowerContent = content.toLowerCase();
        return lowerContent.contains("send") || lowerContent.contains("post") ||
                lowerContent.contains("upload") || lowerContent.contains("save") ||
                lowerContent.contains("store") || lowerContent.contains("log");
    }

    private boolean isSystemLibrarySafe() {
        if (content.contains("com.google.") || content.contains("com.firebase.")) {
            return true;
        }
        if (classContext != null && classContext.isUiLayer && !classContext.isSecureContext()) {
            return true;
        }
        return false;
    }
}