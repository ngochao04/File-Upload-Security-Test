package com.filesecurity.exception;

import com.filesecurity.model.FileRecord;
import com.filesecurity.repository.FileRecordRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.support.MissingServletRequestPartException; // ← thêm import này

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@RestControllerAdvice
@Slf4j
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final FileRecordRepository fileRecordRepository;

    private static final ConcurrentHashMap<String, Long> recentlyHandled = new ConcurrentHashMap<>();

    // ← THÊM HANDLER NÀY VÀO (đặt trước handler Exception.class chung)
    @ExceptionHandler(MissingServletRequestPartException.class)
    public ResponseEntity<Map<String, Object>> handleMissingPart(MissingServletRequestPartException e) {
        log.warn("Missing request part: {}", e.getMessage());
        return ResponseEntity.badRequest().body(Map.of(
            "success", false,
            "message", "Vui lòng chọn file trước khi upload."
        ));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<Map<String, Object>> handleMaxSizeException(
            MaxUploadSizeExceededException e,
            HttpServletRequest request) {

        String clientIp = getClientIp(request);
        long now = System.currentTimeMillis();
        Long last = recentlyHandled.get(clientIp);

        if (last != null && now - last < 2000) {
            return ResponseEntity.badRequest().body(Map.of(
                "success", false,
                "message", "File vượt quá kích thước tối đa cho phép (10MB). Upload bị từ chối."
            ));
        }
        recentlyHandled.put(clientIp, now);

        log.warn("File too large: {}", e.getMessage());

        String originalName = "unknown";
        try {
            String disposition = request.getHeader("Content-Disposition");
            if (disposition != null && disposition.contains("filename=")) {
                originalName = disposition.replaceAll(".*filename=\"?([^\"]+)\"?.*", "$1");
            }
        } catch (Exception ignored) {}

        String reason = "File vượt quá kích thước tối đa cho phép (10MB). Upload bị từ chối.";

        FileRecord record = FileRecord.builder()
            .originalName(originalName)
            .sanitizedName(originalName)
            .storedName("REJECTED_" + UUID.randomUUID())
            .filePath("N/A")
            .fileSize(0L)
            .mimeType("unknown")
            .extension("")
            .uploadStatus(FileRecord.UploadStatus.REJECTED)
            .rejectionReason(reason)
            .uploadedAt(LocalDateTime.now())
            .uploaderIp(clientIp)
            .build();
        fileRecordRepository.save(record);

        return ResponseEntity.badRequest().body(Map.of(
            "success", false,
            "message", reason,
            "validation", Map.of(
                "sizeValid", false,
                "extensionValid", false,
                "mimeTypeValid", false,
                "nameClean", false
            )
        ));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneral(Exception e) {
        log.error("Unexpected error: {}", e.getMessage());
        return ResponseEntity.internalServerError().body(Map.of(
            "success", false,
            "message", "Lỗi hệ thống: " + e.getMessage()
        ));
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        return request.getRemoteAddr();
    }
}