package com.secure.analyzer.controllers;

import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.core.io.ByteArrayResource;

import java.io.*;
import java.nio.file.*;
import java.util.Map;

/**
 * AIAnalysisController — Pipeline IA SÉPARÉ du pipeline statique existant.
 *
 * ❌ Ne touche PAS à APKAnalyzerController ni UltimateAnalyzer.
 * ✅ Routes dédiées : /api/ai/analyze  /api/ai/chat  /ai-report
 *
 * Prérequis : le micro-service Python doit tourner sur http://localhost:5001
 *   → lancer : uvicorn ai_service:app --port 5001 --reload
 */
@Controller
public class AIAnalysisController {

    private static final String UPLOAD_DIR    = "uploads/";
    private static final String AI_SERVICE_URL = "http://localhost:5001";

    private final RestTemplate restTemplate = new RestTemplate();

    // ─────────────────────────────────────────────────────────
    // POST /api/ai/analyze
    //   • Reçoit l'APK depuis le frontend
    //   • Transmet au micro-service Python
    //   • Stocke le rapport JSON en session
    // ─────────────────────────────────────────────────────────
    @PostMapping("/api/ai/analyze")
    @ResponseBody
    public ResponseEntity<String> analyzeWithAI(
            @RequestParam("file") MultipartFile file,
            HttpSession session) {

        try {
            // 1. Sauvegarder l'APK temporairement
            Files.createDirectories(Paths.get(UPLOAD_DIR));
            String apkPath = UPLOAD_DIR + "ai_" + System.currentTimeMillis()
                             + "_" + file.getOriginalFilename();
            file.transferTo(Paths.get(apkPath));

            System.out.println("🤖 [AI] Analyse IA de : " + apkPath);

            // 2. Envoyer l'APK au service Python via multipart/form-data
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.MULTIPART_FORM_DATA);

            byte[] apkBytes = Files.readAllBytes(Paths.get(apkPath));
            ByteArrayResource apkResource = new ByteArrayResource(apkBytes) {
                @Override
                public String getFilename() {
                    return file.getOriginalFilename();
                }
            };

            MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
            body.add("file", apkResource);

            HttpEntity<MultiValueMap<String, Object>> requestEntity =
                    new HttpEntity<>(body, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    AI_SERVICE_URL + "/analyze",
                    HttpMethod.POST,
                    requestEntity,
                    String.class
            );

            // 3. Stocker le rapport JSON en session pour la page /ai-report
            session.setAttribute("aiReport", response.getBody());
            session.setAttribute("apkName", file.getOriginalFilename());

            // 4. Nettoyer le fichier temporaire
            Files.deleteIfExists(Paths.get(apkPath));

            System.out.println("✅ [AI] Rapport reçu du service Python");
            return ResponseEntity.ok("{\"status\":\"ok\"}");

        } catch (Exception e) {
            e.printStackTrace();
            // Message d'erreur lisible pour le frontend
            String msg = e.getMessage() != null ? e.getMessage() : "Erreur inconnue";
            if (msg.contains("Connection refused")) {
                msg = "Service IA indisponible — lancez : uvicorn ai_service:app --port 5001";
            }
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(msg);
        }
    }

    // ─────────────────────────────────────────────────────────
    // GET /ai-report
    //   • Récupère le rapport depuis la session
    //   • Affiche ai_report.html
    // ─────────────────────────────────────────────────────────
    @GetMapping("/ai-report")
    public String aiReport(HttpSession session, Model model) {
        String reportJson = (String) session.getAttribute("aiReport");
        String apkName    = (String) session.getAttribute("apkName");

        if (reportJson == null) {
            // Pas de rapport en session → retour à l'accueil
            return "redirect:/";
        }

        model.addAttribute("reportJson", reportJson);
        model.addAttribute("apkName", apkName != null ? apkName : "unknown.apk");
        return "ai_report";
    }

    // ─────────────────────────────────────────────────────────
    // POST /api/ai/chat
    //   • Reçoit un message utilisateur
    //   • Le transmet au service Python /chat
    //   • Retourne la réponse de l'IA
    // ─────────────────────────────────────────────────────────
    @PostMapping("/api/ai/chat")
    @ResponseBody
    public ResponseEntity<String> chat(@RequestBody Map<String, String> payload,
                                       HttpSession session) {
        try {
            String userMessage = payload.get("message");
            if (userMessage == null || userMessage.isBlank()) {
                return ResponseEntity.badRequest().body("{\"reply\":\"Message vide.\"}");
            }

            // Contexte du rapport courant (optionnel, enrichit la réponse IA)
            String reportContext = (String) session.getAttribute("aiReport");

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            // Construire le payload pour le service Python
            String jsonBody = String.format(
                "{\"message\": %s, \"context\": %s}",
                toJsonString(userMessage),
                reportContext != null ? reportContext : "null"
            );

            HttpEntity<String> request = new HttpEntity<>(jsonBody, headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    AI_SERVICE_URL + "/chat",
                    HttpMethod.POST,
                    request,
                    String.class
            );

            return ResponseEntity.ok(response.getBody());

        } catch (Exception e) {
            e.printStackTrace();
            String msg = e.getMessage() != null ? e.getMessage() : "Erreur";
            if (msg.contains("Connection refused")) {
                return ResponseEntity.ok("{\"reply\":\"⚠️ Service IA indisponible. Lancez uvicorn ai_service:app --port 5001\"}");
            }
            return ResponseEntity.ok("{\"reply\":\"Erreur : " + escapeJson(msg) + "\"}");
        }
    }

    // ── Helpers ──────────────────────────────────────────────

    private String toJsonString(String s) {
        return "\"" + escapeJson(s) + "\"";
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
