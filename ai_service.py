"""
ai_service.py — Micro-service IA pour APK Security Analyzer
============================================================
Compatible Quark Engine 26.5.1

Dépendances :
    pip install fastapi uvicorn quark-engine python-multipart anthropic

Lancement :
    python -m uvicorn ai_service:app --host 127.0.0.1 --port 5001 --reload

Variables d'environnement (optionnel) :
    ANTHROPIC_API_KEY=sk-ant-...   → Active le chat LLM réel
    QUARK_DEBUG=1                  → Affiche les tracebacks complets des règles
"""

import os
import json
import shutil
import tempfile
import traceback
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ──────────────────────────────────────────────────────────────
# Initialisation FastAPI
# ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="APK AI Analysis Service",
    description="Analyse IA d'APK Android via Quark Engine + LLM",
    version="2.3.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────
# Détection Quark Engine 26.5.1
# ──────────────────────────────────────────────────────────────
QUARK_AVAILABLE = False
_Quark          = None
_RuleObject     = None
LLM_AVAILABLE   = False
ai_client       = None

try:
    from quark.core.quark import Quark as _QuarkCls

    _RuleObjectCls = None
    for _mod_path in (
        "quark.core.struct.ruleobject",
        "quark.core.rule",
        "quark.rules.ruleobject",
    ):
        try:
            import importlib as _il
            _m = _il.import_module(_mod_path)
            _RuleObjectCls = getattr(_m, "RuleObject", None)
            if _RuleObjectCls:
                print(f"✅ RuleObject trouvé dans {_mod_path}")
                break
        except Exception:
            continue

    if _RuleObjectCls is None:
        raise ImportError("RuleObject introuvable.")

    _Quark      = _QuarkCls
    _RuleObject = _RuleObjectCls
    QUARK_AVAILABLE = True
    print("✅ Quark Engine 26.5.1 disponible")

except Exception as _eq:
    print(f"⚠️  Quark Engine non disponible : {_eq}")
    print("    → pip install quark-engine")

# ── Client Anthropic (optionnel) ──
_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
if _api_key:
    try:
        import anthropic
        ai_client     = anthropic.Anthropic(api_key=_api_key)
        LLM_AVAILABLE = True
        print("✅ Claude LLM disponible")
    except Exception as _e_llm:
        print(f"⚠️  Anthropic SDK non disponible : {_e_llm}")
else:
    print("⚠️  ANTHROPIC_API_KEY absent → chat en mode simulation")


# ──────────────────────────────────────────────────────────────
# RÈGLES QUARK 26.5.1
#
# IMPORTANT — Bug interne Quark 26.5.1 :
#   q.run(rule) lève "list index out of range" quand le champ "api"
#   contient 0 ou 1 entrée. Quark attend EXACTEMENT 2 méthodes API
#   pour corréler un comportement (c'est le modèle 5 étapes de Quark).
#
#   → Toutes les règles basées sur des permissions uniquement (sans API)
#     ou avec une seule API sont analysées via notre fallback statique
#     (scan du manifest / des chaînes de l'APK).
#   → Seules les règles avec ≥ 2 entrées "api" passent par q.run().
# ──────────────────────────────────────────────────────────────

# Règles compatibles Quark (≥ 2 API à corréler)
QUARK_RULE_DEFINITIONS = [
    {
        "id": "WEBVIEW_JS",
        "crime": "WebView avec JavaScript activé",
        "severity": "HIGH", "owasp": "M1",
        "json": {
            "crime": "WebView JavaScript Enabled", "permission": [],
            "api": [
                {"class": "Landroid/webkit/WebSettings;",
                 "method": "setJavaScriptEnabled",
                 "descriptor": "(Z)V"},
                {"class": "Landroid/webkit/WebView;",
                 "method": "addJavascriptInterface",
                 "descriptor": "(Ljava/lang/Object;Ljava/lang/String;)V"}
            ],
            "score": 80, "label": []
        }
    },
    {
        "id": "LOG_SECRET",
        "crime": "Logs contenant des données sensibles",
        "severity": "MEDIUM", "owasp": "M2",
        "json": {
            "crime": "Sensitive Data in Logs", "permission": [],
            "api": [
                {"class": "Landroid/util/Log;", "method": "d",
                 "descriptor": "(Ljava/lang/String;Ljava/lang/String;)I"},
                {"class": "Landroid/util/Log;", "method": "e",
                 "descriptor": "(Ljava/lang/String;Ljava/lang/String;)I"}
            ],
            "score": 60, "label": []
        }
    },
    {
        "id": "SEND_SMS",
        "crime": "Envoi de SMS sans interaction utilisateur",
        "severity": "CRITICAL", "owasp": "M1",
        "json": {
            "crime": "Silent SMS Sending",
            "permission": ["android.permission.SEND_SMS"],
            "api": [
                {"class": "Landroid/telephony/SmsManager;",
                 "method": "sendTextMessage",
                 "descriptor": "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V"},
                {"class": "Landroid/telephony/SmsManager;",
                 "method": "getDefault",
                 "descriptor": "()Landroid/telephony/SmsManager;"}
            ],
            "score": 90, "label": []
        }
    },
    {
        "id": "DYNAMIC_DEXLOAD",
        "crime": "Chargement de code dynamique (DEX)",
        "severity": "HIGH", "owasp": "M7",
        "json": {
            "crime": "Dynamic DEX Loading", "permission": [],
            "api": [
                {"class": "Ldalvik/system/DexClassLoader;",
                 "method": "<init>",
                 "descriptor": "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V"},
                {"class": "Ljava/lang/ClassLoader;",
                 "method": "loadClass",
                 "descriptor": "(Ljava/lang/String;)Ljava/lang/Class;"}
            ],
            "score": 80, "label": []
        }
    },
    {
        "id": "RUNTIME_EXEC",
        "crime": "Exécution de commande système",
        "severity": "HIGH", "owasp": "M7",
        "json": {
            "crime": "Execute System Command", "permission": [],
            "api": [
                {"class": "Ljava/lang/Runtime;",
                 "method": "getRuntime",
                 "descriptor": "()Ljava/lang/Runtime;"},
                {"class": "Ljava/lang/Runtime;",
                 "method": "exec",
                 "descriptor": "(Ljava/lang/String;)Ljava/lang/Process;"}
            ],
            "score": 80, "label": []
        }
    },
    {
        "id": "SQL_INJECTION",
        "crime": "Concaténation SQL dangereuse",
        "severity": "HIGH", "owasp": "M7",
        "json": {
            "crime": "SQL Injection Pattern", "permission": [],
            "api": [
                {"class": "Ljava/lang/StringBuilder;",
                 "method": "append",
                 "descriptor": "(Ljava/lang/String;)Ljava/lang/StringBuilder;"},
                {"class": "Landroid/database/sqlite/SQLiteDatabase;",
                 "method": "rawQuery",
                 "descriptor": "(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"}
            ],
            "score": 85, "label": []
        }
    },
    {
        "id": "CRYPTO_WEAK",
        "crime": "Utilisation d'algorithme cryptographique faible (MD5/DES)",
        "severity": "MEDIUM", "owasp": "M5",
        "json": {
            "crime": "Weak Crypto Algorithm", "permission": [],
            "api": [
                {"class": "Ljava/security/MessageDigest;",
                 "method": "getInstance",
                 "descriptor": "(Ljava/lang/String;)Ljava/security/MessageDigest;"},
                {"class": "Ljava/security/MessageDigest;",
                 "method": "update",
                 "descriptor": "([B)V"}
            ],
            "score": 70, "label": []
        }
    },
    {
        "id": "LOCATION_TRACK",
        "crime": "Suivi de localisation en arrière-plan",
        "severity": "HIGH", "owasp": "M2",
        "json": {
            "crime": "Background Location Tracking",
            "permission": ["android.permission.ACCESS_FINE_LOCATION"],
            "api": [
                {"class": "Landroid/location/LocationManager;",
                 "method": "requestLocationUpdates",
                 "descriptor": "(Ljava/lang/String;JFLandroid/location/LocationListener;)V"},
                {"class": "Landroid/location/LocationManager;",
                 "method": "getLastKnownLocation",
                 "descriptor": "(Ljava/lang/String;)Landroid/location/Location;"}
            ],
            "score": 80, "label": []
        }
    },
]

# ──────────────────────────────────────────────────────────────
# Règles statiques (manifest + scan de chaînes)
# Analysées sans Quark car elles n'ont pas 2 API à corréler
# ──────────────────────────────────────────────────────────────
STATIC_RULE_DEFINITIONS = [
    {
        "id": "ALLOW_BACKUP",
        "crime": "android:allowBackup activé",
        "severity": "MEDIUM", "owasp": "M2",
        "manifest_attr": "android:allowBackup",
        "match_value": "true",
    },
    {
        "id": "DEBUGGABLE",
        "crime": "Application en mode debuggable",
        "severity": "HIGH", "owasp": "M2",
        "manifest_attr": "android:debuggable",
        "match_value": "true",
    },
    {
        "id": "CLEARTEXT_TRAFFIC",
        "crime": "Trafic en clair autorisé",
        "severity": "MEDIUM", "owasp": "M3",
        "manifest_attr": "android:usesCleartextTraffic",
        "match_value": "true",
    },
    {
        "id": "READ_SMS",
        "crime": "Permission de lecture des SMS",
        "severity": "HIGH", "owasp": "M2",
        "permission": "android.permission.READ_SMS",
    },
    {
        "id": "ACCESSIBILITY_SERVICE",
        "crime": "Abus du service d'accessibilité",
        "severity": "HIGH", "owasp": "M2",
        "permission": "android.permission.BIND_ACCESSIBILITY_SERVICE",
    },
    {
        "id": "CAMERA_MIC",
        "crime": "Accès simultané caméra + micro",
        "severity": "HIGH", "owasp": "M2",
        "permissions_all": [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
        ],
    },
    {
        "id": "HTTP_URL",
        "crime": "URLs HTTP non sécurisées dans le code",
        "severity": "MEDIUM", "owasp": "M3",
        "string_contains": "http://",
    },
    {
        "id": "HARDCODED_SECRET",
        "crime": "Secrets potentiellement codés en dur",
        "severity": "HIGH", "owasp": "M2",
        "string_patterns": ["password=", "api_key=", "secret=", "token=", "Bearer "],
    },
    {
        "id": "EXPORTED_COMPONENT",
        "crime": "Composant Android exporté sans protection",
        "severity": "HIGH", "owasp": "M2",
        "manifest_attr": "android:exported",
        "match_value": "true",
    },
    {
        "id": "UNSAFE_BACKUP",
        "crime": "Sauvegarde non sécurisée (fullBackupContent)",
        "severity": "MEDIUM", "owasp": "M2",
        "manifest_attr": "android:fullBackupContent",
        "match_value": "true",
    },
]


# ──────────────────────────────────────────────────────────────
# Analyse statique (fallback sans Quark)
# ──────────────────────────────────────────────────────────────
def _run_static_analysis(apk_path: str) -> list:
    """
    Analyse statique légère : dézippe l'APK, lit AndroidManifest.xml (binaire→texte)
    et scanne les fichiers .dex/.smali pour des patterns connus.
    Retourne une liste de findings.
    """
    import zipfile, re

    findings = []
    manifest_text = ""
    dex_strings   = ""

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            # Lire le manifest (binaire XML → on cherche les chaînes lisibles)
            if "AndroidManifest.xml" in z.namelist():
                raw = z.read("AndroidManifest.xml")
                # Le manifest Android binaire contient les chaînes en UTF-16LE
                # On extrait les chaînes ASCII/UTF-8 lisibles
                manifest_text = raw.decode("utf-8", errors="replace")

            # Lire les classes.dex (chercher des chaînes)
            for name in z.namelist():
                if name.endswith(".dex"):
                    raw = z.read(name)
                    # Extraire les chaînes ASCII du DEX (longueur > 4)
                    dex_strings += " ".join(
                        s.decode("ascii", errors="replace")
                        for s in re.findall(rb'[ -~]{5,}', raw)
                    )
    except Exception as e:
        print(f"   ⚠️  [static] Erreur lecture APK : {e}")
        return findings

    combined = manifest_text + " " + dex_strings

    for rule in STATIC_RULE_DEFINITIONS:
        matched = False
        confidence = "100%"

        try:
            if "manifest_attr" in rule:
                # Ex: android:allowBackup="true"
                pattern = rf'{rule["manifest_attr"]}[^"]*"{rule["match_value"]}"'
                matched = bool(re.search(pattern, combined, re.IGNORECASE))

            elif "permission" in rule:
                matched = rule["permission"] in combined

            elif "permissions_all" in rule:
                matched = all(p in combined for p in rule["permissions_all"])

            elif "string_contains" in rule:
                matched = rule["string_contains"] in combined
                confidence = "80%"

            elif "string_patterns" in rule:
                matched = any(p.lower() in combined.lower() for p in rule["string_patterns"])
                confidence = "75%"

        except Exception as e:
            print(f"   ⚠️  [static/{rule['id']}] {e}")
            continue

        status = "✅" if matched else "  "
        print(f"   {status} [static/{rule['id']}] matched={matched}")

        if matched:
            findings.append({
                "id":         rule["id"],
                "crime":      rule["crime"],
                "severity":   rule["severity"],
                "confidence": confidence,
                "owasp":      rule["owasp"],
            })

    return findings


# ──────────────────────────────────────────────────────────────
# Analyse Quark (règles avec ≥ 2 API)
# ──────────────────────────────────────────────────────────────
RULES_DIR = Path(tempfile.gettempdir()) / "quark_rules_apkanalyzer"
RULES_DIR.mkdir(exist_ok=True)


def _write_rule_file(rule_def: dict) -> str:
    rule_path = RULES_DIR / f"{rule_def['id']}.json"
    with open(rule_path, "w", encoding="utf-8") as f:
        json.dump(rule_def["json"], f, indent=2)
    return str(rule_path)


def _score_check_item(check_item) -> int:
    """Convertit check_item Quark 26.x en pourcentage 0-100."""
    if not check_item:
        return 0
    total_steps = 5
    passed = 0
    for item in check_item[:total_steps]:
        try:
            if isinstance(item, bool):
                passed += int(item)
            elif isinstance(item, (list, tuple, set)):
                passed += 1 if len(item) > 0 else 0
            elif item:
                passed += 1
        except Exception:
            pass
    return int(passed / total_steps * 100)


def _run_quark_rules(apk_path: str) -> list:
    """Lance Quark sur les règles avec ≥ 2 API. Retourne une liste de findings."""
    if not QUARK_AVAILABLE:
        return []

    findings = []

    for rule_def in QUARK_RULE_DEFINITIONS:
        rule_path = _write_rule_file(rule_def)
        try:
            q    = _Quark(apk_path)
            rule = _RuleObject(rule_path)

            # q.run() peut crasher en interne sur certaines règles/APK
            # On l'attrape et on tente de lire check_item quand même
            run_error = None
            try:
                q.run(rule)
            except Exception as re_:
                run_error = re_
                if os.environ.get("QUARK_DEBUG"):
                    traceback.print_exc()

            # Lire check_item même si run() a partiellement planté
            check_item = getattr(rule, "check_item", None)
            if check_item is not None:
                conf_val = _score_check_item(check_item)
            elif run_error is None:
                # Pas de check_item et pas d'erreur → on tente confidence
                raw = getattr(rule, "confidence", "0%") or "0%"
                try:
                    conf_val = int(str(raw).replace("%", "").strip())
                except (ValueError, AttributeError):
                    conf_val = 0
            else:
                # run() a planté et pas de check_item → on skip
                print(f"   ⚠️  [quark/{rule_def['id']}] run() échoué : {run_error}")
                continue

            print(f"   [quark/{rule_def['id']}] confidence={conf_val}%")

            if conf_val >= 60:
                findings.append({
                    "id":         rule_def["id"],
                    "crime":      rule_def["crime"],
                    "severity":   rule_def["severity"],
                    "confidence": f"{conf_val}%",
                    "owasp":      rule_def["owasp"],
                })

        except Exception as e:
            print(f"   ⚠️  [quark/{rule_def['id']}] erreur inattendue : {e}")
            if os.environ.get("QUARK_DEBUG"):
                traceback.print_exc()

    return findings


# ──────────────────────────────────────────────────────────────
# Orchestrateur principal
# ──────────────────────────────────────────────────────────────
def run_full_analysis(apk_path: str) -> dict:
    """Combine analyse Quark + analyse statique."""
    print(f"\n   → Analyse Quark (règles comportementales)…")
    quark_findings  = _run_quark_rules(apk_path)

    print(f"   → Analyse statique (manifest + patterns)…")
    static_findings = _run_static_analysis(apk_path)

    # Fusion sans doublons (Quark est prioritaire)
    seen     = {f["id"] for f in quark_findings}
    findings = quark_findings + [f for f in static_findings if f["id"] not in seen]

    crimes_detected = [f["crime"] for f in findings]
    risk_score = sum(
        {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10}.get(f["severity"], 5)
        for f in findings
    )

    engine = "Quark Engine 26.5.1 + Analyse statique"
    if not QUARK_AVAILABLE:
        engine = "Analyse statique uniquement (Quark indisponible)"

    return _build_final_report(apk_path, findings, crimes_detected, risk_score, engine)


# ──────────────────────────────────────────────────────────────
# Construction du rapport
# ──────────────────────────────────────────────────────────────
def _build_final_report(apk_path, findings, crimes_detected, risk_score, engine):
    risk_score = min(risk_score, 100)

    if   risk_score >= 70: risk_level = "CRITICAL"
    elif risk_score >= 45: risk_level = "HIGH"
    elif risk_score >= 20: risk_level = "MEDIUM"
    else:                  risk_level = "LOW"

    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high     = sum(1 for f in findings if f["severity"] == "HIGH")
    medium   = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low      = len(findings) - critical - high - medium

    return {
        "engine":           engine,
        "apk":              Path(apk_path).name,
        "risk_level":       risk_level,
        "risk_score":       risk_score,
        "summary":          _build_summary(risk_level, crimes_detected),
        "crimes_detected":  crimes_detected,
        "findings":         findings,
        "stats": {
            "total":    len(findings),
            "critical": critical,
            "high":     high,
            "medium":   medium,
            "low":      low,
        },
        "recommendations":  _build_recommendations(findings),
        "owasp_categories": list({f["owasp"] for f in findings}),
    }


def _build_summary(risk_level: str, crimes: list) -> str:
    if not crimes:
        return "✅ Aucun comportement malveillant détecté."
    n = len(crimes)
    return (
        f"Analyse combinée (Quark + statique) : {n} problème(s) détecté(s). "
        f"Niveau de risque global : {risk_level}. "
        f"Principaux : {', '.join(crimes[:3])}{'…' if n > 3 else ''}."
    )


def _build_recommendations(findings: list) -> list:
    recs, seen = [], set()
    MAP = {
        "SEND_SMS":
            "Supprimer SmsManager.sendTextMessage() ou exiger une confirmation utilisateur explicite.",
        "DYNAMIC_DEXLOAD":
            "Éviter DexClassLoader en production. Utiliser Android App Bundle + Play Feature Delivery.",
        "RUNTIME_EXEC":
            "Remplacer Runtime.exec() par ProcessBuilder avec une liste d'arguments fixes.",
        "CRYPTO_WEAK":
            "Remplacer MD5/SHA-1 par SHA-256. Remplacer DES/ECB par AES/GCM/NoPadding 256 bits.",
        "LOCATION_TRACK":
            "Supprimer ACCESS_BACKGROUND_LOCATION si non nécessaire. Justifier requestLocationUpdates().",
        "WEBVIEW_JS":
            "Désactiver setJavaScriptEnabled() si inutile. Valider les URLs. Activer Safe Browsing.",
        "SQL_INJECTION":
            "Utiliser des requêtes paramétrées : rawQuery(\"SELECT * FROM t WHERE id=?\", new String[]{input})",
        "DEBUGGABLE":
            "Définir android:debuggable=\"false\" dans le manifest de production.",
        "ALLOW_BACKUP":
            "Définir android:allowBackup=\"false\" pour éviter l'extraction via adb backup.",
        "HARDCODED_SECRET":
            "Ne jamais stocker clés/tokens en dur. Utiliser Android Keystore ou un coffre-fort de secrets.",
        "READ_SMS":
            "Supprimer READ_SMS si possible. Utiliser l'API SMS Retriever pour les OTP.",
        "ACCESSIBILITY_SERVICE":
            "Justifier et documenter l'usage d'AccessibilityService — souvent signalé comme spyware.",
        "CLEARTEXT_TRAFFIC":
            "Définir android:usesCleartextTraffic=\"false\" et configurer une Network Security Config.",
        "EXPORTED_COMPONENT":
            "Ajouter android:exported=\"false\" ou protéger avec une permission personnalisée.",
        "LOG_SECRET":
            "Supprimer les Log.d/e contenant des données sensibles. Conditionner avec BuildConfig.DEBUG.",
        "HTTP_URL":
            "Remplacer toutes les URLs http:// par https://. Activer le Certificate Pinning.",
        "CAMERA_MIC":
            "Justifier l'accès simultané caméra + micro. Informer l'utilisateur clairement.",
        "UNSAFE_BACKUP":
            "Implémenter BackupAgent pour contrôler précisément les données sauvegardées.",
    }
    for f in findings:
        fid = f["id"]
        if fid not in seen:
            seen.add(fid)
            if fid in MAP:
                recs.append(MAP[fid])
    if not recs:
        recs.append("Aucune recommandation critique. Continuez les bonnes pratiques OWASP MASVS.")
    return recs


# ──────────────────────────────────────────────────────────────
# Modèles Pydantic
# ──────────────────────────────────────────────────────────────
class ChatRequest(BaseModel):
    message: str
    context: Optional[dict] = None


# ──────────────────────────────────────────────────────────────
# ENDPOINT  POST /analyze
# ──────────────────────────────────────────────────────────────
@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Le fichier doit être un .apk")

    tmp_dir  = Path(tempfile.gettempdir()) / "apk_ai_analysis"
    tmp_dir.mkdir(exist_ok=True)
    apk_path = tmp_dir / file.filename

    try:
        with open(apk_path, "wb") as buf:
            shutil.copyfileobj(file.file, buf)

        print(f"\n🤖 Analyse de : {apk_path.name}")
        report = run_full_analysis(str(apk_path))
        print(f"✅ Terminé — risque : {report['risk_level']} ({report['risk_score']}/100) "
              f"| {report['stats']['total']} finding(s)")
        return report

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        try:
            apk_path.unlink(missing_ok=True)
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────
# ENDPOINT  POST /chat
# ──────────────────────────────────────────────────────────────
@app.post("/chat")
async def chat(request: ChatRequest):
    user_msg = request.message.strip()
    if not user_msg:
        return {"reply": "Message vide."}
    if LLM_AVAILABLE and ai_client:
        return await _chat_with_claude(user_msg, request.context)
    return {"reply": _simulated_chat(user_msg, request.context)}


async def _chat_with_claude(user_msg: str, context: Optional[dict]) -> dict:
    try:
        system_prompt = (
            "You are a world-class Android security expert specializing in OWASP MASVS, "
            "APK reverse engineering, malware analysis, and mobile penetration testing. "
            "Answer concisely and technically. Always provide actionable fixes. "
            "Respond in the same language as the user (French if they write in French)."
        )
        context_block = ""
        if context and isinstance(context, dict):
            findings_str  = json.dumps(context.get("findings", []), ensure_ascii=False, indent=2)
            context_block = (
                f"\n\n[RAPPORT APK ANALYSÉE]\n"
                f"APK: {context.get('apk','?')} | Risque: {context.get('risk_level','?')}\n"
                f"Score: {context.get('risk_score','?')}/100\n"
                f"Findings:\n{findings_str}"
            )
        response = ai_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=system_prompt,
            messages=[{"role": "user", "content": user_msg + context_block}]
        )
        return {"reply": response.content[0].text if response.content else "Aucune réponse."}
    except Exception as e:
        traceback.print_exc()
        return {"reply": f"⚠️ Erreur LLM : {str(e)}"}


def _simulated_chat(user_msg: str, context: Optional[dict]) -> str:
    m = user_msg.lower()
    if any(w in m for w in ["sql", "injection"]):
        return (
            "**SQL Injection Android — OWASP M7**\n\n"
            "❌ `rawQuery(\"SELECT * FROM t WHERE id=\" + input, null)`\n\n"
            "✅ Fix : `db.rawQuery(\"SELECT * FROM t WHERE id=?\", new String[]{input})`\n\n"
            "Référence : MASVS-STORAGE-2"
        )
    elif any(w in m for w in ["sms", "send_sms", "sendtextmessage"]):
        return (
            "**SMS malveillant — OWASP M1**\n\n"
            "Exfiltration via `SmsManager.sendTextMessage()` sans consentement.\n\n"
            "✅ Fix : confirmation utilisateur obligatoire. Alternative : API SMS Retriever."
        )
    elif any(w in m for w in ["dex", "dexclassloader", "dynamic", "dynamique"]):
        return (
            "**DexClassLoader — OWASP M7**\n\n"
            "Charge du code arbitraire contournant le Play Store.\n\n"
            "✅ Fix : Android App Bundle + Play Feature Delivery.\n"
            "Si indispensable → vérifier signature + hash SHA-256 du DEX."
        )
    elif any(w in m for w in ["crypto", "md5", "sha", "chiffrement", "encryption", "des", "ecb"]):
        return (
            "**Cryptographie faible — OWASP M5**\n\n"
            "MD5/SHA-1 cassés. DES/ECB trivial à briser.\n\n"
            "✅ Fix :\n"
            "- Hash → SHA-256 / SHA-3\n"
            "- Symétrique → AES/GCM/NoPadding 256 bits\n"
            "- Asymétrique → RSA/OAEP 2048+ bits\n"
            "- KDF → PBKDF2 / Argon2"
        )
    elif any(w in m for w in ["webview", "javascript", "js", "addjavascriptinterface"]):
        return (
            "**WebView Security — OWASP M1**\n\n"
            "`setJavaScriptEnabled(true)` + `addJavascriptInterface()` = RCE via XSS.\n\n"
            "✅ Fix :\n"
            "- Désactiver JS si inutile\n"
            "- Valider toutes les URLs\n"
            "- `WebView.setSafeBrowsingEnabled(true)`\n"
            "- Supprimer `addJavascriptInterface()` si possible"
        )
    elif any(w in m for w in ["owasp", "masvs", "top 10", "top10"]):
        return (
            "**OWASP Mobile Top 10**\n\n"
            "M1: Improper Platform Usage\nM2: Insecure Data Storage\n"
            "M3: Insecure Communication\nM4: Insecure Authentication\n"
            "M5: Insufficient Cryptography\nM6: Insecure Authorization\n"
            "M7: Client Code Quality\nM8: Code Tampering\n"
            "M9: Reverse Engineering\nM10: Extraneous Functionality"
        )
    elif any(w in m for w in ["quark", "quark engine", "ruleobject"]):
        return (
            "**Quark Engine 26.5.1 — Notes d'intégration**\n\n"
            "⚠️ Bug connu : `q.run()` lève `list index out of range` si la règle\n"
            "contient moins de 2 entrées `api`. Quark corrèle toujours 2 méthodes.\n\n"
            "✅ Solution : toutes les règles à 0 ou 1 API passent par\n"
            "l'analyse statique (manifest + scan DEX) de ce service."
        )
    elif any(w in m for w in ["permission", "manifest", "backup", "debuggable", "exported"]):
        return (
            "**Permissions & Manifest — OWASP M2**\n\n"
            "✅ Bonnes pratiques :\n"
            "- `android:exported=\"false\"` pour composants internes\n"
            "- `android:allowBackup=\"false\"` en production\n"
            "- `android:debuggable=\"false\"` en release\n"
            "- Network Security Config pour bloquer HTTP"
        )
    elif any(w in m for w in ["location", "gps", "localisation", "tracking"]):
        return (
            "**Tracking de localisation — OWASP M2**\n\n"
            "✅ Fix :\n"
            "- Préférer ACCESS_COARSE_LOCATION\n"
            "- Supprimer ACCESS_BACKGROUND_LOCATION si inutile\n"
            "- Rationale dialog obligatoire"
        )
    elif any(w in m for w in ["log", "logcat", "secret", "token", "password", "mot de passe"]):
        return (
            "**Secrets dans les logs — OWASP M2**\n\n"
            "Les logs sont lisibles via `adb logcat`.\n\n"
            "✅ Fix :\n"
            "- Supprimer les Log.* avec données sensibles\n"
            "- `if (BuildConfig.DEBUG) Log.d(...)`\n"
            "- ProGuard/R8 supprime les logs en release"
        )
    else:
        level = (context or {}).get("risk_level", "")
        score = (context or {}).get("risk_score", "")
        n     = (context or {}).get("stats", {}).get("total", 0)
        base  = f"APK analysée : risque **{level}** ({score}/100), {n} finding(s).\n\n" if level else ""
        return (
            base +
            "Mode simulation (ANTHROPIC_API_KEY absent).\n\n"
            "Pour activer Claude :\n"
            "```\nset ANTHROPIC_API_KEY=sk-ant-...\n"
            "python -m uvicorn ai_service:app --port 5001 --reload\n```\n\n"
            "Questions : SQL injection, DexClassLoader, WebView, crypto, "
            "permissions, OWASP MASVS, Quark Engine, localisation, logs…"
        )


# ──────────────────────────────────────────────────────────────
# ENDPOINT  GET /health
# ──────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status":               "ok",
        "version":              "2.3.0",
        "quark_available":      QUARK_AVAILABLE,
        "llm_available":        LLM_AVAILABLE,
        "quark_rules_count":    len(QUARK_RULE_DEFINITIONS),
        "static_rules_count":   len(STATIC_RULE_DEFINITIONS),
        "total_rules":          len(QUARK_RULE_DEFINITIONS) + len(STATIC_RULE_DEFINITIONS),
        "engine":               "Quark 26.5.1 + Analyse statique" if QUARK_AVAILABLE else "Analyse statique uniquement",
        "llm_api":              "claude-sonnet-4-20250514" if LLM_AVAILABLE else "simulation",
        "debug_mode":           bool(os.environ.get("QUARK_DEBUG")),
    }
