package com.filesecurity.service;

import com.filesecurity.model.UploadResult;
import lombok.extern.slf4j.Slf4j;
import org.apache.tika.Tika;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

@Service
@Slf4j
public class FileValidationService {

    private static final Pattern DANGEROUS_PATTERN =
        Pattern.compile(".*(\\.php|\\.jsp|\\.asp|\\.exe|\\.sh|\\.bat|\\.cmd|\\.py|\\.rb|\\.pl).*",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern PATH_TRAVERSAL_PATTERN =
        Pattern.compile(".*(\\.\\./|\\.\\.\\\\|%2e%2e|%252e).*", Pattern.CASE_INSENSITIVE);

    private static final Pattern NULL_BYTE_PATTERN =
        Pattern.compile(".*(%00|\\u0000).*");

    private static final Pattern CLEAN_NAME_PATTERN =
        Pattern.compile("[^a-zA-Z0-9._\\-]");

    private final Tika tika = new Tika();

    @Value("${app.upload.max-size-bytes}")
    private long maxSizeBytes;

    @Value("${app.upload.allowed-types}")
    private String allowedTypesStr;

    @Value("${app.upload.allowed-extensions}")
    private String allowedExtensionsStr;

    public UploadResult.ValidationDetail validate(MultipartFile file) throws IOException {
        String originalName = file.getOriginalFilename() != null ? file.getOriginalFilename() : "";
        String extension = extractExtension(originalName);
        String detectedMime = tika.detect(file.getInputStream());
        long fileSize = file.getSize();
        String sanitized = sanitizeFileName(originalName);

        boolean extensionValid = isExtensionAllowed(extension);
        boolean mimeTypeValid = isMimeTypeAllowed(detectedMime);
        boolean sizeValid = fileSize > 0 && fileSize <= maxSizeBytes;
        boolean nameClean = isNameSafe(originalName);

        return UploadResult.ValidationDetail.builder()
            .extensionValid(extensionValid)
            .mimeTypeValid(mimeTypeValid)
            .sizeValid(sizeValid)
            .nameClean(nameClean)
            .detectedMimeType(detectedMime)
            .fileExtension(extension)
            .fileSizeBytes(fileSize)
            .sanitizedFileName(sanitized)
            .build();
    }

    public String sanitizeFileName(String fileName) {
        if (fileName == null || fileName.isBlank()) return "unnamed_file";

        // Remove path traversal
        String sanitized = fileName.replaceAll("\\.\\./", "").replaceAll("\\.\\.\\\\", "");

        // Remove null bytes
        sanitized = sanitized.replace("\u0000", "").replace("%00", "");

        // Get only the filename, not path
        int lastSlash = Math.max(sanitized.lastIndexOf('/'), sanitized.lastIndexOf('\\'));
        if (lastSlash >= 0) sanitized = sanitized.substring(lastSlash + 1);

        // Replace dangerous chars - keep only alphanumeric, dots, dashes, underscores
        sanitized = CLEAN_NAME_PATTERN.matcher(sanitized).replaceAll("_");

        // Prevent empty result
        if (sanitized.isBlank() || sanitized.equals(".")) sanitized = "unnamed_file";

        // Limit length
        if (sanitized.length() > 100) sanitized = sanitized.substring(0, 100);

        return sanitized;
    }

    public boolean isExtensionAllowed(String extension) {
        List<String> allowed = Arrays.asList(allowedExtensionsStr.split(","));
        return allowed.stream().anyMatch(ext -> ext.trim().equalsIgnoreCase(extension));
    }

    public boolean isMimeTypeAllowed(String mimeType) {
        List<String> allowed = Arrays.asList(allowedTypesStr.split(","));
        return allowed.stream().anyMatch(type -> type.trim().equalsIgnoreCase(mimeType));
    }

    public boolean isNameSafe(String fileName) {
        if (fileName == null) return false;
        if (PATH_TRAVERSAL_PATTERN.matcher(fileName).matches()) return false;
        if (NULL_BYTE_PATTERN.matcher(fileName).matches()) return false;
        if (DANGEROUS_PATTERN.matcher(fileName).matches()) return false;
        return true;
    }

    public String extractExtension(String fileName) {
        if (fileName == null || !fileName.contains(".")) return "";
        // Get the LAST extension (defend against double extensions like evil.php.jpg)
        String lastExt = fileName.substring(fileName.lastIndexOf('.') + 1);
        return lastExt.toLowerCase().trim();
    }

    public String getAllowedExtensions() {
        return allowedExtensionsStr;
    }

    public long getMaxSizeBytes() {
        return maxSizeBytes;
    }
}
