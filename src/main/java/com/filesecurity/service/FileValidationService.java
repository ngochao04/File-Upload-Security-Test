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

    // ❌ ĐÃ XÓA: PATH_TRAVERSAL_PATTERN – không còn kiểm tra path traversal
    // ❌ ĐÃ XÓA: NULL_BYTE_PATTERN     – không còn kiểm tra null byte

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

        // ✅ THAY ĐỔI 3 – MIME type: luôn trả về true, KHÔNG kiểm tra MIME thực tế
        // Trước: isMimeTypeAllowed(detectedMime) → phát hiện file giả mạo (evil.php đổi .jpg)
        // Sau:   true → evil.php.jpg / shell.jpg đều PASS mime check → Upload thành công
        boolean mimeTypeValid = true;

        // ✅ THAY ĐỔI 1 – File size: nới lỏng lên 50MB, bỏ chặn 0 byte
        // Trước: fileSize > 0 && fileSize <= maxSizeBytes (10MB)
        // Sau:   fileSize <= 52428800L (50MB)
        //        → file 0 byte: PASS (kỳ vọng FAIL)
        //        → file 15MB:   PASS (kỳ vọng FAIL)
        boolean sizeValid = fileSize <= 52428800L;

        // ✅ THAY ĐỔI 2 – Filename security: luôn trả về true
        // Trước: isNameSafe() kiểm tra path traversal + null byte → reject
        // Sau:   bỏ qua hoàn toàn
        //        → ../../etc/passwd.jpg: PASS (kỳ vọng FAIL)
        //        → file%00.php.jpg:      PASS (kỳ vọng FAIL)
        boolean nameClean = true;

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

        String sanitized = fileName.replaceAll("\\.\\./", "").replaceAll("\\.\\.\\\\", "");
        sanitized = sanitized.replace("\u0000", "").replace("%00", "");

        int lastSlash = Math.max(sanitized.lastIndexOf('/'), sanitized.lastIndexOf('\\'));
        if (lastSlash >= 0) sanitized = sanitized.substring(lastSlash + 1);

        sanitized = CLEAN_NAME_PATTERN.matcher(sanitized).replaceAll("_");

        if (sanitized.isBlank() || sanitized.equals(".")) sanitized = "unnamed_file";

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

    // isNameSafe() giữ lại để tham khảo nhưng không còn được gọi trong validate()
    public boolean isNameSafe(String fileName) {
        if (fileName == null) return false;
        String pathTraversalRegex = ".*(\\.\\./|\\.\\.\\\\|%2e%2e|%252e).*";
        String nullByteRegex = ".*(%00|\\u0000).*";
        if (Pattern.compile(pathTraversalRegex, Pattern.CASE_INSENSITIVE).matcher(fileName).matches()) return false;
        if (Pattern.compile(nullByteRegex).matcher(fileName).matches()) return false;
        if (DANGEROUS_PATTERN.matcher(fileName).matches()) return false;
        return true;
    }

    public String extractExtension(String fileName) {
        if (fileName == null || !fileName.contains(".")) return "";

        // ✅ THAY ĐỔI 4 – Double extension: lấy extension ĐẦU TIÊN thay vì cuối cùng
        // Trước: fileName.lastIndexOf('.') → "evil.php.jpg" lấy "jpg" → extension check = jpg (PASS)
        //        rồi MIME Tika phát hiện php → bị chặn ở mime check
        // Sau:   lấy first extension → "evil.php.jpg" → firstExt = "php"
        //        → extension check FAIL vì "php" không trong whitelist
        //        → kết quả thực tế: Từ chối vì extension (không phải vì MIME)
        //        → test case TC-EP-05 mong đợi "Từ chối vì MIME" nhưng thực tế "Từ chối vì extension"
        //           → kết quả sai lệch so với mong đợi → FAIL
        int firstDot = fileName.indexOf('.');
        String afterFirstDot = fileName.substring(firstDot + 1);
        String firstExt = afterFirstDot.contains(".")
            ? afterFirstDot.substring(0, afterFirstDot.indexOf('.'))
            : afterFirstDot;
        return firstExt.toLowerCase().trim();
    }

    public String getAllowedExtensions() {
        return allowedExtensionsStr;
    }

    public long getMaxSizeBytes() {
        return maxSizeBytes;
    }
}