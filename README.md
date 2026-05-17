# 🔒 SecureAPK Analyzer — AI Enhanced Edition

[![Java](https://img.shields.io/badge/Java-17-blue.svg)](https://java.com)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.14-brightgreen.svg)](https://spring.io)
[![Python](https://img.shields.io/badge/Python-3.10+-yellow.svg)](https://python.org)
[![Quark Engine](https://img.shields.io/badge/Quark-26.5.1-purple.svg)](https://github.com/quark-engine/quark-engine)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

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

### 🧪 Analyse statique fallback

Même sans Quark :

* Permissions dangereuses
* Secrets en dur
* HTTP non sécurisé
* Debuggable
* Exported components

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
