package com.filesecurity.controller;

import com.filesecurity.model.FileRecord;
import com.filesecurity.model.UploadResult;
import com.filesecurity.service.FileUploadService;
import com.filesecurity.service.FileValidationService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequiredArgsConstructor
public class FileUploadController {

    private final FileUploadService uploadService;
    private final FileValidationService validationService;

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("allowedExtensions", validationService.getAllowedExtensions());
        model.addAttribute("maxSizeMB", validationService.getMaxSizeBytes() / (1024 * 1024));
        model.addAttribute("totalSuccess", uploadService.countSuccess());
        model.addAttribute("totalRejected", uploadService.countRejected());
        model.addAttribute("totalStorage", FileUploadService.formatSize(uploadService.totalStorage()));
        return "index";
    }

    @PostMapping("/upload")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> upload(
            @RequestParam("file") MultipartFile file,
            HttpServletRequest request) {

        UploadResult result = uploadService.uploadFile(file, request);
        Map<String, Object> response = new HashMap<>();
        response.put("success", result.isSuccess());
        response.put("message", result.getMessage());
        response.put("originalName", result.getOriginalName());
        response.put("sanitizedName", result.getSanitizedName());
        response.put("storedName", result.getStoredName());
        response.put("mimeType", result.getMimeType());

        if (result.getValidationDetail() != null) {
            UploadResult.ValidationDetail d = result.getValidationDetail();
            Map<String, Object> validation = new HashMap<>();
            validation.put("extensionValid", d.isExtensionValid());
            validation.put("mimeTypeValid", d.isMimeTypeValid());
            validation.put("sizeValid", d.isSizeValid());
            validation.put("nameClean", d.isNameClean());
            validation.put("detectedMimeType", d.getDetectedMimeType());
            validation.put("fileExtension", d.getFileExtension());
            validation.put("fileSizeBytes", d.getFileSizeBytes());
            validation.put("fileSizeFormatted", FileUploadService.formatSize(d.getFileSizeBytes()));
            validation.put("sanitizedFileName", d.getSanitizedFileName());
            response.put("validation", validation);
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/history")
    @ResponseBody
    public ResponseEntity<List<FileRecord>> history() {
        return ResponseEntity.ok(uploadService.getAllRecords());
    }

    @GetMapping("/stats")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> stats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalSuccess", uploadService.countSuccess());
        stats.put("totalRejected", uploadService.countRejected());
        stats.put("totalStorage", FileUploadService.formatSize(uploadService.totalStorage()));
        return ResponseEntity.ok(stats);
    }
}
