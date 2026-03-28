package com.filesecurity.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<Map<String, Object>> handleMaxSizeException(MaxUploadSizeExceededException e) {
        log.warn("File too large: {}", e.getMessage());
        return ResponseEntity.badRequest().body(Map.of(
            "success", false,
            "message", "File vượt quá kích thước tối đa cho phép (10MB). Upload bị từ chối.",
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
}
