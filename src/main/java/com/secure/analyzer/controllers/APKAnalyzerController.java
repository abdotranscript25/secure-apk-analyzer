package com.secure.analyzer.controllers;

import com.secure.analyzer.analyzers.UltimateAnalyzer;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.*;

@Controller
public class APKAnalyzerController {

    private static final String UPLOAD_DIR = "uploads/";

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @PostMapping("/analyze")
    public String analyze(@RequestParam("file") MultipartFile file, Model model) {
        try {
            // 1. Créer le dossier uploads s'il n'existe pas
            Files.createDirectories(Paths.get(UPLOAD_DIR));

            // 2. Sauvegarder l'APK
            String apkPath = UPLOAD_DIR + System.currentTimeMillis() + "_" + file.getOriginalFilename();
            file.transferTo(Paths.get(apkPath));

            System.out.println("📱 Analyse de: " + apkPath);

            // 3. Analyser avec UltimateAnalyzer
            UltimateAnalyzer.UltimateReport report = UltimateAnalyzer.analyze(apkPath);

            // 4. Nettoyer le fichier temporaire
            Files.deleteIfExists(Paths.get(apkPath));

            // 5. Envoyer le rapport au template
            model.addAttribute("report", report);

            return "report";

        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", e.getMessage());
            return "error";
        }
    }
}