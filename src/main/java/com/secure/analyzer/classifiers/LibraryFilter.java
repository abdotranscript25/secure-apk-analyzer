package com.secure.analyzer.classifiers;

import java.util.Set;

/**
 * Filtre les classes provenant de bibliothèques tierces (AndroidX, Firebase, Google, etc.)
 * pour éviter les faux positifs.
 */
public class LibraryFilter {

    private static final Set<String> KNOWN_LIB_PREFIXES = Set.of(
            // Android / Jetpack
            "android/",
            "androidx/",
            "com/android/",
            "android/support/",

            // Google / Firebase
            "com/google/",
            "com/firebase/",
            "firebase/",

            // Kotlin
            "kotlin/",
            "kotlinx/",

            // Réseau
            "okhttp3/",
            "retrofit2/",
            "okio/",
            "io/grpc/",

            // Apache
            "org/apache/",

            // Facebook
            "com/facebook/",

            // Square
            "com/squareup/",

            // Injection
            "dagger/",
            "javax/",

            // Crypto
            "org/bouncycastle/",
            "org/spongycastle/",

            // Reactive
            "io/reactivex/",
            "org/reactivestreams/",

            // Logging
            "org/slf4j/",
            "org/apache/logging/",

            // JSON
            "com/fasterxml/",
            "com/google/gson/",
            "org/json/",

            // JetBrains
            "org/jetbrains/",

            // Jeu de tests
            "junit/",
            "org/mockito/",
            "org/hamcrest/",
            "android/test/"
    );

    /**
     * Détermine si un fichier Java appartient à une bibliothèque tierce.
     *
     * @param filePath Chemin complet du fichier (absolu)
     * @return true si c'est une librairie à ignorer, false si c'est du code applicatif
     */
    public static boolean isThirdParty(String filePath) {
        if (filePath == null) return true;

        String normalized = filePath.replace("\\", "/").toLowerCase();

        // Ignorer tout ce qui n'est pas dans le dossier sources/ (fichiers générés)
        if (!normalized.contains("/sources/")) return true;

        // Extraire le chemin après /sources/
        int sourcesIndex = normalized.indexOf("/sources/");
        if (sourcesIndex < 0) return true;

        String afterSources = normalized.substring(sourcesIndex + 9);

        // Vérifier les préfixes de librairies connues
        for (String prefix : KNOWN_LIB_PREFIXES) {
            if (afterSources.startsWith(prefix)) {
                return true;
            }
        }

        // Heuristique : les packages très profonds (>= 8 niveaux) sont souvent des librairies
        int depth = afterSources.split("/").length;
        if (depth > 8) {
            return true;
        }

        // Heuristique : classes auto-générées
        if (afterSources.contains("r$") ||
                afterSources.contains("buildconfig") ||
                afterSources.contains("databinding") ||
                afterSources.contains("generated") ||
                afterSources.contains("_generated")) {
            return true;
        }

        // Heuristique : fichiers sans package (souvent des librairies)
        if (!afterSources.contains("/")) {
            return true;
        }

        return false;
    }

    /**
     * Version simplifiée qui prend aussi le contenu pour analyse complémentaire.
     * Permet de détecter certaines librairies par leur contenu.
     */
    public static boolean isThirdParty(String filePath, String content) {
        // D'abord vérifier par chemin
        if (isThirdParty(filePath)) {
            return true;
        }

        if (content == null || content.isEmpty()) {
            return false;
        }

        // Vérifier par contenu : certaines librairies n'ont pas de chemin typique
        String lowerContent = content.toLowerCase();

        // AndroidX
        if (lowerContent.contains("androidx.") && !lowerContent.contains("package com.")) {
            return true;
        }

        // Google Play Services
        if (lowerContent.contains("com.google.android.gms") ||
                lowerContent.contains("com.google.firebase")) {
            return true;
        }

        // Kotlin runtime
        if (lowerContent.contains("kotlin.jvm") ||
                lowerContent.contains("kotlin.coroutines")) {
            return true;
        }

        return false;
    }
}