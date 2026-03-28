package com.filesecurity.service;

import com.filesecurity.model.FileRecord;
import com.filesecurity.model.UploadResult;
import com.filesecurity.repository.FileRecordRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class FileUploadService {

    private final FileValidationService validationService;
    private final FileRecordRepository fileRecordRepository;

    @Value("${app.upload.dir}")
    private String uploadDir;

    public UploadResult uploadFile(MultipartFile file, HttpServletRequest request) {
        String clientIp = getClientIp(request);
        String originalName = file.getOriginalFilename() != null ? file.getOriginalFilename() : "unknown";

        log.info("Upload attempt: file='{}', size={}, ip={}", originalName, file.getSize(), clientIp);

        try {
            // === VALIDATION ===
            UploadResult.ValidationDetail detail = validationService.validate(file);

            // Check all validations
            if (!detail.isExtensionValid()) {
                return saveAndReturn(false, originalName, detail, clientIp,
                    "Loại file không được phép: ." + detail.getFileExtension() +
                    ". Chỉ chấp nhận: " + validationService.getAllowedExtensions(),
                    FileRecord.UploadStatus.REJECTED);
            }

            if (!detail.isMimeTypeValid()) {
                return saveAndReturn(false, originalName, detail, clientIp,
                    "MIME type thực tế '" + detail.getDetectedMimeType() + "' không hợp lệ. " +
                    "Phát hiện file giả mạo định dạng!",
                    FileRecord.UploadStatus.REJECTED);
            }

            if (!detail.isSizeValid()) {
                String reason = file.getSize() == 0
                    ? "File rỗng (0 bytes) không được phép upload"
                    : "Kích thước file " + formatSize(file.getSize()) +
                      " vượt quá giới hạn " + formatSize(validationService.getMaxSizeBytes());
                return saveAndReturn(false, originalName, detail, clientIp, reason,
                    FileRecord.UploadStatus.REJECTED);
            }

            if (!detail.isNameClean()) {
                return saveAndReturn(false, originalName, detail, clientIp,
                    "Tên file chứa ký tự nguy hiểm (Path Traversal / Null Byte / Script injection)",
                    FileRecord.UploadStatus.REJECTED);
            }

            // === SAFE STORAGE ===
            Path uploadPath = Paths.get(uploadDir).toAbsolutePath().normalize();
            Files.createDirectories(uploadPath);

            // Generate UUID-based stored name to prevent enumeration
            String storedName = UUID.randomUUID() + "_" + detail.getSanitizedFileName();
            Path targetPath = uploadPath.resolve(storedName).normalize();

            // Ensure target is within upload dir (prevent path traversal in storage)
            if (!targetPath.startsWith(uploadPath)) {
                return saveAndReturn(false, originalName, detail, clientIp,
                    "Path traversal attack detected in storage path",
                    FileRecord.UploadStatus.QUARANTINED);
            }

            Files.copy(file.getInputStream(), targetPath, StandardCopyOption.REPLACE_EXISTING);

            // Save record to DB
            FileRecord record = FileRecord.builder()
                .originalName(originalName)
                .sanitizedName(detail.getSanitizedFileName())
                .storedName(storedName)
                .filePath(targetPath.toString())
                .fileSize(file.getSize())
                .mimeType(detail.getDetectedMimeType())
                .extension(detail.getFileExtension())
                .uploadStatus(FileRecord.UploadStatus.SUCCESS)
                .uploadedAt(LocalDateTime.now())
                .uploaderIp(clientIp)
                .build();
            fileRecordRepository.save(record);

            log.info("Upload SUCCESS: stored as '{}'", storedName);

            return UploadResult.builder()
                .success(true)
                .message("Upload thành công! File đã được kiểm tra và lưu trữ an toàn.")
                .originalName(originalName)
                .sanitizedName(detail.getSanitizedFileName())
                .storedName(storedName)
                .fileSize(file.getSize())
                .mimeType(detail.getDetectedMimeType())
                .validationDetail(detail)
                .build();

        } catch (IOException e) {
            log.error("Upload error: {}", e.getMessage());
            return UploadResult.builder()
                .success(false)
                .message("Lỗi server khi xử lý file: " + e.getMessage())
                .originalName(originalName)
                .build();
        }
    }

    private UploadResult saveAndReturn(boolean success, String originalName,
                                        UploadResult.ValidationDetail detail,
                                        String clientIp, String reason,
                                        FileRecord.UploadStatus status) {
        FileRecord record = FileRecord.builder()
            .originalName(originalName)
            .sanitizedName(detail != null ? detail.getSanitizedFileName() : originalName)
            .storedName("N/A")
            .filePath("N/A")
            .fileSize(detail != null ? detail.getFileSizeBytes() : 0L)
            .mimeType(detail != null ? detail.getDetectedMimeType() : "unknown")
            .extension(detail != null ? detail.getFileExtension() : "")
            .uploadStatus(status)
            .rejectionReason(reason)
            .uploadedAt(LocalDateTime.now())
            .uploaderIp(clientIp)
            .build();
        fileRecordRepository.save(record);

        log.warn("Upload REJECTED: file='{}', reason='{}'", originalName, reason);

        return UploadResult.builder()
            .success(false)
            .message(reason)
            .originalName(originalName)
            .rejectionReason(reason)
            .validationDetail(detail)
            .build();
    }

    public List<FileRecord> getAllRecords() {
        return fileRecordRepository.findAllByOrderByUploadedAtDesc();
    }

    public long countSuccess() {
        return fileRecordRepository.countSuccessful();
    }

    public long countRejected() {
        return fileRecordRepository.countRejected();
    }

    public Long totalStorage() {
        Long total = fileRecordRepository.totalStorageUsed();
        return total != null ? total : 0L;
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    public static String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        else if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        else return String.format("%.1f MB", bytes / (1024.0 * 1024));
    }
}
