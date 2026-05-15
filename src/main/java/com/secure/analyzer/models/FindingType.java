package com.secure.analyzer.models;

/**
 * Types de vulnérabilités / findings — v3.0
 */
public enum FindingType {

    // Manifest
    BACKUP_CONFIGURATION,
    DEBUGGABLE,
    CLEARTEXT_TRAFFIC,
    OUTDATED_SDK,
    EXPORTED_COMPONENT,
    TASK_AFFINITY,
    NETWORK_SECURITY,

    // Permissions
    DANGEROUS_PERMISSION,

    // Code
    DANGEROUS_CODE,
    SQL_INJECTION,
    WEBVIEW_VULNERABILITY,
    SENSITIVE_LOG,
    HARDCODED_SECRET,
    INSECURE_RANDOM,

    // Crypto
    WEAK_CRYPTOGRAPHY,
    INSECURE_CIPHER_MODE,

    // Réseau
    INSECURE_CONNECTION,
    SSL_BYPASS,

    // Données
    INFORMATION_DISCLOSURE,
    INTERNAL_FILE,
    LOG_FILE,
}