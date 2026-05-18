# 🔒 SecureAPK Analyzer — AI Enhanced Edition

[![Java](https://img.shields.io/badge/Java-17-blue.svg)](https://java.com)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.14-brightgreen.svg)](https://spring.io)
[![Python](https://img.shields.io/badge/Python-3.10+-yellow.svg)](https://python.org)
[![Quark Engine](https://img.shields.io/badge/Quark-26.5.1-purple.svg)](https://github.com/quark-engine/quark-engine)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

# Section IA :

## 🚀 Description

**SecureAPK Analyzer — AI Edition** est une évolution avancée de l’outil d’analyse d’APK Android.

👉 Il introduit une **architecture hybride** combinant :

* 🔍 Analyse statique (Java / Spring Boot)
* 🤖 Analyse IA via micro-service Python
* 🧠 Détection comportementale avec Quark Engine
* 💬 Chat IA interactif basé sur le rapport

---

## 🧠 Nouveautés (Mises à jour)

### 🔥 Pipeline IA séparé

| Composant                   | Rôle                                    |
| --------------------------- | --------------------------------------- |
| `AIAnalysisController.java` | Connecte Spring Boot au microservice IA |
| `ai_service.py`             | Analyse IA (Quark + heuristique + LLM)  |
| `ai_report.html`            | Interface dédiée aux résultats IA       |
| `/api/ai/chat`              | Chat intelligent basé sur le rapport    |

---

## 🏗️ Architecture globale

```
UTILISATEUR
   │
   ▼
Frontend (index.html)
   │
   ├──────────────► Pipeline STATIQUE (UltimateAnalyzer)
   │
   └──────────────► Pipeline IA (NOUVEAU)
                      │
                      ▼
        AIAnalysisController (Spring Boot)
                      │
                      ▼
        Microservice Python (FastAPI)
                      │
        ├── Quark Engine (détection comportementale)
        ├── Analyse statique fallback
        └── (Optionnel) LLM Claude
                      │
                      ▼
                Rapport JSON
                      │
                      ▼
               ai_report.html
                      │
                      ▼
                 Chat IA
```

---

## ⚙️ Installation

### 🔧 Prérequis

| Outil  | Version |
| ------ | ------- |
| Java   | 17+     |
| Maven  | 3.6+    |
| Python | 3.10+   |
| pip    | latest  |

---

## 🐍 Installation du microservice IA

```bash
# Aller à la racine du projet
cd secure-apk-analyzer

# Installer les dépendances Python
pip install fastapi uvicorn quark-engine python-multipart anthropic
```

---

## ▶️ Lancer le microservice IA

```bash
python -m uvicorn ai_service:app --host 127.0.0.1 --port 5001 --reload
```

📌 Endpoint disponible :

```
http://localhost:5001
```

---

## ☕ Lancer l'application Spring Boot

```bash
# Compiler
./mvnw clean package

# Lancer
./mvnw spring-boot:run
```

---

## 🌐 Accès application

```
http://localhost:8080
```

---

## 📊 Utilisation

### 🔍 Analyse IA d’un APK

1. Aller sur la page principale
2. Uploader un fichier `.apk`
3. Cliquer sur **Analyse IA**
4. Redirection vers :

```
/ai-report
```

---

### 💬 Chat IA

Après analyse :

* Pose des questions comme :

  * "Explique la SQL Injection"
  * "Pourquoi c’est dangereux ?"
  * "Comment corriger ?"

👉 Le chat utilise :

* le rapport JSON
* le contexte de sécurité

---

## ⚡ Endpoints API

### 📦 Analyse IA

```
POST /api/ai/analyze
```

Upload APK → retourne status → stocke rapport en session

---

### 📊 Rapport IA

```
GET /ai-report
```

Affiche le rapport IA

---

### 💬 Chat IA

```
POST /api/ai/chat
```

Body :

```json
{
  "message": "Explique cette vulnérabilité"
}
```

---

### ❤️ Health Check

```
GET /health
```

Retourne :

```json
{
  "status": "ok",
  "quark_available": true,
  "llm_available": false
}
```

---

## 🧠 Moteur IA

### 🔍 Quark Engine (détection comportementale)

Détecte :

| Type              | Exemple                |
| ----------------- | ---------------------- |
| SMS malveillant   | `sendTextMessage`      |
| Dynamic code      | `DexClassLoader`       |
| Command execution | `Runtime.exec`         |
| SQL Injection     | `rawQuery + concat`    |
| WebView exploit   | `setJavaScriptEnabled` |

---



### 🤖 LLM (optionnel)

Active avec :

```bash
set ANTHROPIC_API_KEY=sk-ant-xxxx
```

Sinon → mode simulation intelligent

---

## 📁 Structure des nouveaux fichiers

```
src/
 └── main/
     └── java/com/secure/analyzer/controllers/
         └── AIAnalysisController.java   ✅

resources/templates/
 ├── index.html        🔄 (modifié)
 └── ai_report.html    🆕

/ (racine)
 └── ai_service.py     🆕
```

---

## ⚠️ Points importants

### ❗ Microservice obligatoire

Si erreur :

```
Connection refused
```

👉 lancer :

```bash
uvicorn ai_service:app --port 5001
```

---

### ❗ Quark Engine

Si absent :

```bash
pip install quark-engine
```

Sinon → fallback automatique

---

## 🧩 Différence avec version précédente

| Feature                | Avant | Maintenant |
| ---------------------- | ----- | ---------- |
| Analyse IA             | ❌     | ✅          |
| Microservice           | ❌     | ✅          |
| Chat IA                | ❌     | ✅          |
| Quark Engine           | ❌     | ✅          |
| Architecture modulaire | ❌     | ✅          |

---

## 🎯 Objectif du projet

Créer une plateforme capable de :

* 🔍 détecter des vulnérabilités avancées
* 🧠 comprendre le comportement malware
* 💬 expliquer les risques automatiquement
* ⚡ être plus rapide que MobSF

---

# Section Analyse Statique :


**SecureAPK Analyzer** est un outil d'analyse statique d'APK Android inspiré de [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF).
Il combine **analyse statique traditionnelle** (80+ règles) et **IA comportementale** pour détecter les vulnérabilités et comportements malveillants.



## ✨ Fonctionnalités

### 📱 Analyse statique complète

| Composant | Détections |
|-----------|------------|
| **AndroidManifest.xml** | Permissions dangereuses, `allowBackup`, `debuggable`, `cleartextTraffic`, composants exportés |
| **Code Java décompilé** | `Runtime.exec`, `DexClassLoader`, SQL injection, WebView vulnérable |
| **Ressources XML** | Secrets dans `strings.xml`, configuration réseau |
| **Bibliothèques natives (.so)** | Chaînes ASCII, secrets potentiels |
| **Fallback DEX** | Lecture brute quand JADX échoue (APK obfusquées) |

### 🧠 IA comportementale — `AIBehaviorAnalyzer`

| Pattern détecté | Verdict | Score |
|-----------------|---------|-------|
| SMS + Internet + Secrets | Exfiltration de données | +40 |
| Accessibility + SMS | Spyware | +50 |
| Caméra + Micro + Internet | Surveillance | +35 |

### 📊 Prédiction de risque — `RiskPredictor`

| Feature | Poids |
|---------|-------|
| `READ_SMS` | 0.90 |
| `BIND_ACCESSIBILITY_SERVICE` | 0.95 |
| `SQL_INJECTION` | 0.92 |
| `HARDCODED_SECRET` | 0.88 |

### 🎯 80+ règles de détection

| Catégorie | Exemples |
|-----------|----------|
| **Secrets** | JWT, API keys (AWS, Google, Stripe), mots de passe, clés PEM |
| **Code dangereux** | `Runtime.exec`, `DexClassLoader`, `ProcessBuilder` |
| **Crypto faible** | MD5, SHA-1, DES, RC4, ECB |
| **WebView** | `setJavaScriptEnabled(true)`, `addJavascriptInterface` |
| **Réseau** | URLs HTTP, IPs internes |
| **Logs** | `Log.d/e/i` contenant password/token/secret |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                  APPLICATION WEB (Spring Boot)                      │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                  FRONTEND (Thymeleaf)                         │  │
│  │  ┌──────────────┐   Upload APK   ┌───────────────────────┐   │  │
│  │  │  index.html  │ ─────────────► │     report.html       │   │  │
│  │  │  (upload)    │                │  (résultats + onglets) │   │  │
│  │  └──────────────┘                └───────────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                               │                                     │
│                               ▼                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │              APKAnalyzerController.java                       │  │
│  │  • Reçoit l'APK uploadée                                      │  │
│  │  • Sauvegarde dans uploads/                                   │  │
│  │  • Appelle UltimateAnalyzer.analyze()                         │  │
│  │  • Envoie les résultats au template HTML                      │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                               │                                     │
│                               ▼                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │              UltimateAnalyzer.java (CŒUR)                     │  │
│  │                                                               │  │
│  │  [1/5] extractApk()          → Décompression (ZIP)           │  │
│  │  [2/5] decompileWithJadx()   → .dex → .java                  │  │
│  │         └── Fallback: analyzeDexStrings() si échec            │  │
│  │  [3/5] analyzeManifest()     → AndroidManifest.xml           │  │
│  │  [4/5] analyzeResources()    → XML, strings.xml, .so         │  │
│  │  [5/5] analyzeAllJavaFiles() → 80+ règles                    │  │
│  │  calculateScore()            → 100 - 15C - 8H - 3M - L       │  │
│  └──────────────┬─────────────────────┬────────────────────┬────┘  │
│                 │                     │                    │        │
│                 ▼                     ▼                    ▼        │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────┐    │
│  │  AIBehavior      │  │  RiskPredictor   │  │ UltimateReport │    │
│  │  Analyzer        │  │                  │  │                │    │
│  │                  │  │  Scoring pondéré │  │ • Score 0-100  │    │
│  │  SMS+Internet    │  │  (Naive Bayes)   │  │ • Grade A+ à F │    │
│  │  → exfil +40     │  │  • Poids/feature │  │ • Findings     │    │
│  │  Acc+SMS         │  │  • Confiance 0-1 │  │ • Recommand.   │    │
│  │  → spyware +50   │  │                  │  │                │    │
│  └──────────────────┘  └──────────────────┘  └────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📍 Ordre d'exécution

```
ÉTAPE 0 — Utilisateur
  └── http://localhost:8080 → upload APK → clic "Analyser"
        ↓
ÉTAPE 1 — APKAnalyzerController
  └── Reçoit l'APK → sauvegarde → appelle UltimateAnalyzer.analyze()
        ↓
ÉTAPE 2 — UltimateAnalyzer (ANALYSE STATIQUE)
  ├── [1/5] extractApk()           → Décompresse l'APK (format ZIP)
  ├── [2/5] decompileWithJadx()    → .dex → .java
  │         └── Fallback: analyzeDexStrings() si JADX échoue
  ├── [3/5] analyzeManifest()      → Permissions, debuggable, cleartext...
  ├── [4/5] analyzeResources()     → strings.xml, XML, fichiers .so
  └── [5/5] analyzeAllJavaFiles()  → 80+ règles :
            ├── LibraryFilter.isThirdParty()   → ignore les librairies
            ├── SECRET_PATTERNS                → API keys, JWT, passwords
            ├── CODE_RULES                     → Runtime.exec, DexClassLoader
            ├── SQL_INJECTION_PATTERN          → rawQuery avec +
            ├── WEBVIEW patterns               → setJavaScriptEnabled
            ├── SENSITIVE_LOG_PATTERN          → Log.d("password:" + pwd)
            ├── WEAK_CRYPTO_PATTERN            → MD5, SHA-1, DES
            └── HTTP_URL_PATTERN               → http://...
        ↓
ÉTAPE 3 — AIBehaviorAnalyzer (IA COMPORTEMENTALE)
  ├── Extrait les features (SMS, Internet, secrets...)
  ├── Corrèle les patterns comportementaux
  │   ├── SMS + Internet + Secrets   → exfiltration (+40)
  │   ├── Accessibility + SMS        → spyware (+50)
  │   └── Caméra + Micro + Internet  → surveillance (+35)
  └── Détermine verdict : SAFE / SUSPICIOUS / HIGH_RISK / MALWARE
        ↓
ÉTAPE 4 — RiskPredictor (PRÉDICTION DE RISQUE)
  ├── Calcule score = Σ(poids × 20) + bonus sévérité
  ├── Calcule confiance (0-1 selon nombre de findings)
  └── Détermine catégorie : SAFE / SUSPICIOUS / HIGH_RISK / MALWARE
        ↓
ÉTAPE 5 — UltimateReport.calculateScore()
  ├── Score = 100 - (15×CRITICAL) - (8×HIGH) - (3×MEDIUM) - LOW
  └── Grade : A+ (≥90), A (≥80), B (≥70), C (≥60), D (≥50), F (<50)
        ↓
ÉTAPE 6 — report.html (AFFICHAGE)
  ├── Score principal + Grade + Niveau de risque
  ├── Verdict IA comportementale
  ├── Prédiction de risque + confiance
  ├── Onglets : Manifest, Permissions, Code, Réseau, Crypto, Données
  └── Recommandations
```

---

## 🔧 Composants détaillés

### 1. `UltimateAnalyzer.java` — Cœur de l'analyse

| Méthode | Rôle |
|---------|------|
| `analyze()` | Orchestre les 5 étapes |
| `extractApk()` | Décompresse l'APK (format ZIP) |
| `decompileWithJadx()` | Appelle jadx (.dex → .java) |
| `analyzeManifest()` | Analyse `AndroidManifest.xml` |
| `analyzeAllJavaFiles()` | Parcourt tous les fichiers Java avec 80+ règles |
| `analyzeDexStrings()` | Fallback quand JADX échoue |
| `calculateScore()` | Calcule score 0-100 |

### 2. `LibraryFilter.java` — Filtre des librairies tierces

```java
// Ignore les bibliothèques pour éviter les faux positifs
LIBRARY_PREFIXES = {
    "android.", "androidx.", "com.google.", "com.firebase.",
    "kotlin.", "okhttp3.", "retrofit2.", "org.apache."
}
```

### 3. `ClassContext.java` — Contexte de classe

| Champ | Détection |
|-------|-----------|
| `usesWebView` | `WebView`, `addJavascriptInterface` |
| `usesCrypto` | `Cipher`, `SecretKey`, `MessageDigest` |
| `usesNetwork` | `HttpURLConnection`, `OkHttpClient` |
| `usesDatabase` | `SQLiteDatabase`, `rawQuery` |
| `isActivity` | `extends AppCompatActivity` |

### 4. `AIBehaviorAnalyzer.java` — IA comportementale

```java
// Pattern 1 : Exfiltration de données
if (sms && internet && secrets) score += 40;

// Pattern 2 : Spyware
if (accessibility && sms) score += 50;

// Pattern 3 : Surveillance
if (microphone && camera && internet) score += 35;
```

### 5. `RiskPredictor.java` — Prédiction de risque

```java
// Poids des features (inspiré Naive Bayes)
FEATURE_WEIGHTS.put("READ_SMS",                   0.90);
FEATURE_WEIGHTS.put("BIND_ACCESSIBILITY_SERVICE", 0.95);
FEATURE_WEIGHTS.put("SQL_INJECTION",              0.92);
FEATURE_WEIGHTS.put("HARDCODED_SECRET",           0.88);

// Score = Σ(poids × 20) + bonus sévérité
// Confiance = basée sur le nombre de findings
```

### 6. `UltimateReport.java` — Structure du rapport

| Champ | Type |
|-------|------|
| `securityScore` | `0-100` |
| `securityGrade` | `A+`, `A`, `B`, `C`, `D`, `F` |
| `riskLevel` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `criticalCount` | Nombre de vulnérabilités CRITICAL |
| `manifestFindings` | `List<SecurityFinding>` |
| `codeFindings` | `List<SecurityFinding>` |

---

## 🛠️ Technologies utilisées

| Technologie | Version | Rôle |
|-------------|---------|------|
| Java | 17 | Langage |
| Spring Boot | 3.5.14 | Framework web |
| Thymeleaf | - | Templates HTML |
| JADX | 1.5.5 | Décompilation DEX → Java |
| Maven | 3.6+ | Gestion des dépendances |

---

## 🚀 Installation

### Prérequis

| Outil | Version | Vérification |
|-------|---------|--------------|
| Java | 17+ | `java -version` |
| Maven | 3.6+ | `mvn -version` |
| JADX | 1.5.5+ *(optionnel)* | `jadx --version` |

### Étapes

```bash
# 1. Cloner le repository
git clone https://github.com/votre-compte/secure-apk-analyzer.git
cd secure-apk-analyzer

# 2. Compiler
./mvnw clean package

# 3. Lancer l'application
./mvnw spring-boot:run

# 4. Accéder à l'interface
# Ouvrir http://localhost:8080
```

### Configuration JADX *(optionnel mais recommandé)*

```bash
# Télécharger JADX
wget https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
unzip jadx-1.5.0.zip -d /opt/jadx

# Modifier le chemin dans UltimateAnalyzer.java
# private static final String JADX_PATH = "/opt/jadx/bin/jadx";
```

---

## 📊 Utilisation

### 1. Uploader une APK

```
http://localhost:8080
→ Choisir un fichier .apk
→ Cliquer "Analyser"
```

### 2. Temps d'analyse estimé

| Taille APK | Durée estimée |
|------------|---------------|
| < 5 MB | ~5–10 secondes |
| 5–15 MB | ~10–20 secondes |
| > 15 MB | ~20–40 secondes |

### 3. Le rapport présente

- Score de sécurité (0-100) + Grade (A+ à F)
- Niveau de risque (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`)
- Verdict IA comportementale (`AIBehaviorAnalyzer`)
- Prédiction de risque + confiance (`RiskPredictor`)
- Onglets détaillés : Manifest, Permissions, Code, Réseau, Crypto, Données
- Recommandations de correction

---

## 📈 Résultats

### APK de test — ProjetWS (application vulnérable)

| Sévérité | Nombre |
|----------|--------|
| CRITICAL | 9 |
| HIGH | 6 |
| MEDIUM | 16 |
| LOW | 1 |
| **Total** | **32** |

**Score : 0/100 (F) — Risque CRITICAL**

### Exemples de détections

| Vulnérabilité | Extrait détecté |
|---------------|-----------------|
| `debuggable=true` | `android:debuggable="true"` |
| `cleartextTraffic=true` | `android:usesCleartextTraffic="true"` |
| `Runtime.exec` | `Runtime.getRuntime().exec("su")` |
| `SecretKeySpec` | `new SecretKeySpec(key, "AES")` |
| SHA-1 | `MessageDigest.getInstance("SHA-1")` |
| URL HTTP | `http://192.168.0.162/api` |

---

## 🔬 Comparaison avec MobSF

| Critère | MobSF | SecureAPK Analyzer |
|---------|-------|--------------------|
| Score APK test | 40/100 | 0/100 |
| Temps d'analyse | ~45s | ~12s |
| Détection `checkClientTrusted` | ❌ | ✅ |
| Détection `SecretKeySpec` | ❌ | ✅ |
| Détection SHA-1 | ❌ | ✅ |
| Détection certificat debug | ✅ | ❌ |
| Précision globale | ~100% | ~85–90% |

---

## ⚠️ Limites

| Limite | Explication | Solution possible |
|--------|-------------|-------------------|
| APK protégées / obfusquées | Anti-décompilation résiste à JADX | Fallback DEX brut |
| Certificat debug | Non détecté | Analyser `META-INF/*.RSA` |
| External Storage | Non détecté | Ajouter pattern dédié |
| Secrets en dur (complexes) | Parfois non capturés | Enrichir les regex |
| Code natif (.so) | Analyse limitée aux chaînes ASCII | Intégrer Ghidra |

---

## Démonstration : 

- Démonstration Analyse par JADEX:
[2026-05-18 00-05-03.zip](https://github.com/user-attachments/files/27934533/2026-05-18.00-05-03.zip)

- Démonstration Analyse par Quark:

https://github.com/user-attachments/assets/a6189d0f-f08d-4b5a-b2d6-d10c00e1075f

---

## 📚 RÉCAPITULATIF – CE QUE NOUS AVONS CONSTRUIT



### 📝 Les points essentiels à retenir

| # | Point clé |
|---|-----------|
| 1 | **APK = ZIP** → extraction avec `ZipInputStream` avant toute analyse |
| 2 | **JADX** transforme les fichiers `.dex` en `.java` lisibles |
| 3 | **LibraryFilter** est indispensable pour éviter les faux positifs sur les libs tierces |
| 4 | **AIBehaviorAnalyzer** corrèle des features pour détecter des comportements complexes |
| 5 | **RiskPredictor** applique des poids par feature (inspiré Naive Bayes) |
| 6 | Le **fallback DEX** garantit l'analyse même si JADX échoue sur une APK obfusquée |
| 7 | Score calculé par déduction : `100 - (15×CRITICAL) - (8×HIGH) - (3×MEDIUM) - LOW` |

---

### 🎯 Compétences acquises

| Compétence | Niveau |
|------------|--------|
| Analyse statique d'APK Android | ✅ Maîtrisé |
| Décompilation DEX avec JADX | ✅ Maîtrisé |
| Détection de vulnérabilités par règles regex | ✅ Maîtrisé |
| IA comportementale (corrélation de patterns) | ✅ Maîtrisé |
| Scoring pondéré (inspiré Naive Bayes) | ✅ Maîtrisé |
| Interface web Spring Boot + Thymeleaf | ✅ Maîtrisé |

---


## 👨‍💻 Auteurs

* **Ait Zidane Salma**
* **El Hachimi Abdelhamid**
* **El Ouatik Mourad**

---

## 📅 Version

| Élément | Valeur           |
| ------- | ---------------- |
| Version | 2.0 (AI Edition) |
| Date    | Mai 2026         |
| Statut  | 🚀 En évolution  |

## 🙏 Remerciements

- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — Inspiration et référence
- [JADX](https://github.com/skylot/jadx) — Décompilation DEX → Java
- [Spring Boot](https://spring.io) — Framework web
- [OWASP MASVS](https://owasp.org/www-project-mobile-app-security/) — Standard de sécurité mobile
