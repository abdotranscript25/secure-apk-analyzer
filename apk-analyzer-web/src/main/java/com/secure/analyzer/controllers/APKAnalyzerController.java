package com.secure.analyzer.controllers;

import com.secure.analyzer.analyzers.UltimateAnalyzer;
import com.secure.analyzer.classifiers.RiskPredictor;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import com.secure.analyzer.ai.AIBehaviorAnalyzer;

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

            // 1. Create upload folder
            Files.createDirectories(Paths.get(UPLOAD_DIR));

            // 2. Save APK
            String apkPath = UPLOAD_DIR + System.currentTimeMillis()
                    + "_" + file.getOriginalFilename();

            file.transferTo(Paths.get(apkPath));

            System.out.println("📱 Analyse de: " + apkPath);

            // 3. Static analysis
            UltimateAnalyzer.UltimateReport report =
                    UltimateAnalyzer.analyze(apkPath);

            AIBehaviorAnalyzer.AIResult ai =
                    AIBehaviorAnalyzer.analyze(report);

            // 4. AI prediction
            RiskPredictor.PredictionResult prediction =
                    RiskPredictor.predict(report);

            // 5. Delete temp file
            try {
                Files.deleteIfExists(Paths.get(apkPath));
            } catch (Exception e) {
                System.err.println("⚠ Impossible de supprimer APK temporaire");
            }

            // 6. Send data to HTML
            model.addAttribute("report", report);
            model.addAttribute("ai", ai);

            model.addAttribute("predictedRisk",
                    prediction.riskCategory);

            model.addAttribute("predictionConfidence",
                    prediction.confidenceScore);

            return "report";

        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", e.getMessage());
            return "error";
        }
    }
}