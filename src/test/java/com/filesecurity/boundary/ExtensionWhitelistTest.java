package com.filesecurity.boundary;

import com.filesecurity.service.FileValidationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Extension Whitelist Test – ExtensionWhitelistTest
 *
 * Dùng @ParameterizedTest để kiểm thử toàn bộ whitelist và blacklist
 * extension một cách gọn gàng, không lặp code.
 *
 * Chạy: mvn test -Dtest=ExtensionWhitelistTest
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("Extension Whitelist Tests (Parameterized)")
class ExtensionWhitelistTest {

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
    // VALID EXTENSIONS – tất cả 11 loại phải PASS
    // ─────────────────────────────────────────────────────────────────────────

    @ParameterizedTest(name = "Extension .{0} phải được phép")
    @ValueSource(strings = {"jpg", "jpeg", "png", "gif", "webp", "pdf", "txt", "doc", "docx", "xls", "xlsx"})
    @DisplayName("TC-WL-01: Tất cả extension hợp lệ trong whitelist đều được chấp nhận")
    void testValidExtensionsAllowed(String ext) {
        assertThat(validationService.isExtensionAllowed(ext))
                .as("Extension ." + ext + " phải nằm trong whitelist")
                .isTrue();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // INVALID EXTENSIONS – các extension nguy hiểm phải BỊ TỪ CHỐI
    // ─────────────────────────────────────────────────────────────────────────

    @ParameterizedTest(name = "Extension .{0} phải bị từ chối")
    @ValueSource(strings = {"php", "php3", "php5", "phtml",
                            "exe", "msi", "com", "bat", "cmd",
                            "sh", "bash", "zsh",
                            "py", "pyc",
                            "rb",
                            "pl",
                            "asp", "aspx",
                            "jsp", "jspx",
                            "js", "ts",
                            "vbs", "vbe",
                            "htaccess", "htpasswd"})
    @DisplayName("TC-WL-02: Các extension nguy hiểm bị từ chối")
    void testDangerousExtensionsRejected(String ext) {
        assertThat(validationService.isExtensionAllowed(ext))
                .as("Extension ." + ext + " phải bị từ chối (không trong whitelist)")
                .isFalse();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CASE INSENSITIVE
    // ─────────────────────────────────────────────────────────────────────────

    @ParameterizedTest(name = "Extension .{0} (uppercase) phải được phép")
    @ValueSource(strings = {"JPG", "JPEG", "PNG", "PDF", "TXT"})
    @DisplayName("TC-WL-03: Whitelist không phân biệt hoa thường")
    void testExtensionCaseInsensitive(String ext) {
        assertThat(validationService.isExtensionAllowed(ext))
                .as("Extension ." + ext + " (uppercase) phải được phép (case-insensitive)")
                .isTrue();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // EDGE CASES
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("TC-WL-04: Extension rỗng '' không được phép")
    void testEmptyExtensionNotAllowed() {
        assertThat(validationService.isExtensionAllowed("")).isFalse();
    }

    @Test
    @DisplayName("TC-WL-05: extractExtension từ tên file không có dấu chấm → rỗng")
    void testExtractExtensionNoExtension() {
        assertThat(validationService.extractExtension("filename_no_ext")).isEqualTo("");
    }

    @Test
    @DisplayName("TC-WL-06: extractExtension tên null → rỗng")
    void testExtractExtensionNull() {
        assertThat(validationService.extractExtension(null)).isEqualTo("");
    }
}
