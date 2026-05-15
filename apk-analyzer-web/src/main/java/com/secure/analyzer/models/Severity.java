package com.secure.analyzer.models;

public enum Severity {
    CRITICAL,   // Données extrêmement sensibles (tokens, mots de passe)
    HIGH,       // Données sensibles (email, téléphone, données santé)
    MEDIUM,     // Informations personnelles non critiques
    LOW,        // Potentiellement sensible, mais faible risque
    INFO        // Information seulement, pas une vulnérabilité
}