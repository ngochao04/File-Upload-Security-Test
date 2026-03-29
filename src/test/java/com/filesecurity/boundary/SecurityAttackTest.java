package com.filesecurity.boundary;

import com.filesecurity.model.UploadResult;
import com.filesecurity.service.FileValidationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Security Attack Test – SecurityAttackTest
 *
 * Kiểm thử các vector tấn công bảo mật thường gặp trong File Upload:
 *   - Path Traversal (../../etc/passwd)
 *   - Null Byte Injection (%00)
 *   - Double Extension (evil.php.jpg)
 *   - Script Injection trong tên file
 *   - MIME Type Spoofing (phát hiện qua Apache Tika)
 *
 * Chạy: mvn test -Dtest=SecurityAttackTest
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Security Attack Tests")
class SecurityAttackTest {

    @InjectMocks
    private FileValidationService validationService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(validationService, "maxSizeBytes", 10485760L);
        ReflectionTestUtils.setField(validationService, "allowedExtensionsStr",
                "jpg,jpeg,png,gif,webp,pdf,txt,doc,docx,xls,xlsx");
        ReflectionTestUtils.setField(validationService, "allowedTypesStr",
                "image/jpeg,image/png,image/gif,image/webp,application/pdf,text/plain");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PATH TRAVERSAL
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("TC-SC-01: Path Traversal Unix (../../etc/passwd.jpg) → sanitize loại bỏ ../")
    void testUnixPathTraversalSanitized() {
        String result = validationService.sanitizeFileName("../../etc/passwd.jpg");

        assertThat(result)
                .as("Path traversal phải bị sanitize")
                .doesNotContain("../")
                .doesNotContain("..")
                .doesNotContain("/etc/")
                .endsWith(".jpg");
        System.out.println("[TC-SC-01] Input: ../../etc/passwd.jpg → Sanitized: " + result);
    }

    @Test
    @DisplayName("TC-SC-02: Path Traversal Windows (..\\..\\windows\\system32.jpg) → sanitize")
    void testWindowsPathTraversalSanitized() {
        String result = validationService.sanitizeFileName("..\\..\\windows\\system32.jpg");

        assertThat(result)
                .doesNotContain("..\\")
                .doesNotContain("windows");
        System.out.println("[TC-SC-02] Input: ..\\..\\windows\\system32.jpg → Sanitized: " + result);
    }

    @Test
    @DisplayName("TC-SC-03: isNameSafe() phát hiện path traversal đúng")
    void testIsNameSafeDetectsPathTraversal() {
        // isNameSafe() vẫn hoạt động đúng dù không được gọi trong validate()
        assertThat(validationService.isNameSafe("../../etc/passwd.jpg")).isFalse();
        assertThat(validationService.isNameSafe("..%2f..%2fetc/passwd.jpg")).isFalse();
        assertThat(validationService.isNameSafe("normal_file.jpg")).isTrue();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NULL BYTE INJECTION
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("TC-SC-04: Null Byte Injection (%00) bị loại bỏ khỏi tên file")
    void testNullByteInjectionSanitized() {
        String result = validationService.sanitizeFileName("file%00.php.jpg");

        assertThat(result)
                .doesNotContain("%00")
                .doesNotContain("\u0000");
        System.out.println("[TC-SC-04] Input: file%00.php.jpg → Sanitized: " + result);
    }

    @Test
    @DisplayName("TC-SC-05: Null Byte Unicode (\\u0000) bị loại bỏ")
    void testUnicodeNullByteSanitized() {
        String result = validationService.sanitizeFileName("file\u0000.php.jpg");

        assertThat(result).doesNotContain("\u0000");
        System.out.println("[TC-SC-05] Input: file\\u0000.php.jpg → Sanitized: " + result);
    }

    @Test
    @DisplayName("TC-SC-06: isNameSafe() phát hiện null byte đúng")
    void testIsNameSafeDetectsNullByte() {
        assertThat(validationService.isNameSafe("file%00.php.jpg")).isFalse();
        assertThat(validationService.isNameSafe("file\u0000.php.jpg")).isFalse();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DOUBLE EXTENSION
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("TC-SC-07: Double extension evil.php.jpg → extractExtension = 'php' → bị từ chối")
    void testDoubleExtensionPhpJpgRejected() throws IOException {
        MockMultipartFile file = new MockMultipartFile(
                "file", "evil.php.jpg", "image/jpeg",
                createFakeJpegBytes()
        );

        UploadResult.ValidationDetail detail = validationService.validate(file);

        assertThat(detail.getFileExtension())
                .as("Double extension phải lấy extension đầu tiên (php)")
                .isEqualTo("php");
        assertThat(detail.isExtensionValid())
                .as("php không trong whitelist → bị từ chối")
                .isFalse();
        System.out.println("[TC-SC-07] evil.php.jpg → ext=" + detail.getFileExtension()
                + ", valid=" + detail.isExtensionValid());
    }

    @Test
    @DisplayName("TC-SC-08: Double extension shell.asp.png → extractExtension = 'asp' → bị từ chối")
    void testDoubleExtensionAspPngRejected() throws IOException {
        MockMultipartFile file = new MockMultipartFile(
                "file", "shell.asp.png", "image/png",
                createFakePngBytes()
        );

        UploadResult.ValidationDetail detail = validationService.validate(file);

        assertThat(detail.getFileExtension()).isEqualTo("asp");
        assertThat(detail.isExtensionValid()).isFalse();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SCRIPT INJECTION IN FILENAME
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("TC-SC-09: XSS trong tên file → ký tự < > bị sanitize")
    void testXssInFileNameSanitized() {
        String result = validationService.sanitizeFileName("<script>alert(1)</script>.jpg");

        assertThat(result)
                .doesNotContain("<")
                .doesNotContain(">")
                .endsWith(".jpg");
        System.out.println("[TC-SC-09] XSS filename → Sanitized: " + result);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MIME TYPE SPOOFING (Apache Tika)
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("TC-SC-10: File PHP đổi tên .jpg → Tika detect đúng MIME (không phải image/jpeg)")
    void testMimeSpoofingTikaDetectsReal() throws IOException {
        // File thực tế là PHP script nhưng đặt tên .jpg
        byte[] phpContent = "<?php system($_GET['cmd']); echo 'hacked'; ?>".getBytes();
        MockMultipartFile file = new MockMultipartFile(
                "file", "shell.jpg", "image/jpeg", phpContent
        );

        UploadResult.ValidationDetail detail = validationService.validate(file);

        // Tika sẽ detect là text/plain hoặc application/x-php (không phải image/jpeg)
        assertThat(detail.getDetectedMimeType())
                .as("Tika phải detect MIME thực tế, không phải image/jpeg")
                .isNotEqualTo("image/jpeg");

        System.out.println("[TC-SC-10] shell.jpg (PHP content) → Tika detected: "
                + detail.getDetectedMimeType());
        System.out.println("[BUG NOTE] mimeTypeValid=" + detail.isMimeTypeValid()
                + " (đáng lẽ phải false nhưng code bypass = true)");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // HELPERS
    // ─────────────────────────────────────────────────────────────────────────

    private byte[] createFakeJpegBytes() {
        return new byte[]{
                (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0,
                0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
                0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00
        };
    }

    private byte[] createFakePngBytes() {
        return new byte[]{
                (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG magic
                0x00, 0x00, 0x00, 0x0D
        };
    }
}
