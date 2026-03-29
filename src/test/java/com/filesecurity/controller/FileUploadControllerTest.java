package com.filesecurity.controller;

import com.filesecurity.model.FileRecord;
import com.filesecurity.model.UploadResult;
import com.filesecurity.repository.FileRecordRepository;
import com.filesecurity.service.FileUploadService;
import com.filesecurity.service.FileValidationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration Test – FileUploadController (MockMvc)
 *
 * Kiểm thử toàn bộ HTTP layer: request mapping, response JSON, HTTP status code.
 * Dùng @WebMvcTest nên chỉ load web layer, không cần DB thật.
 *
 * Chạy: mvn test -Dtest=FileUploadControllerTest
 */
@WebMvcTest(FileUploadController.class)
@ActiveProfiles("test")
@DisplayName("FileUploadController – MockMvc Integration Tests")
class FileUploadControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private FileUploadService uploadService;

    @MockBean
    private FileValidationService validationService;

    @MockBean
    private FileRecordRepository fileRecordRepository;

    private UploadResult.ValidationDetail validDetail;
    private UploadResult successResult;
    private UploadResult rejectedResult;

    @BeforeEach
    void setUp() {
        validDetail = UploadResult.ValidationDetail.builder()
                .extensionValid(true).mimeTypeValid(true)
                .sizeValid(true).nameClean(true)
                .detectedMimeType("image/jpeg")
                .fileExtension("jpg").fileSizeBytes(3145728L)
                .sanitizedFileName("photo.jpg")
                .build();

        successResult = UploadResult.builder()
                .success(true)
                .message("Upload thành công! File đã được kiểm tra và lưu trữ an toàn.")
                .originalName("photo.jpg")
                .sanitizedName("photo.jpg")
                .storedName("uuid_photo.jpg")
                .mimeType("image/jpeg")
                .validationDetail(validDetail)
                .build();

        rejectedResult = UploadResult.builder()
                .success(false)
                .message("Loại file không được phép: .php. Chỉ chấp nhận: jpg,jpeg,png,gif,webp,pdf,txt,doc,docx,xls,xlsx")
                .originalName("shell.php")
                .validationDetail(UploadResult.ValidationDetail.builder()
                        .extensionValid(false).mimeTypeValid(true)
                        .sizeValid(true).nameClean(true)
                        .detectedMimeType("application/x-php")
                        .fileExtension("php").fileSizeBytes(50L)
                        .sanitizedFileName("shell.php")
                        .build())
                .build();

        when(validationService.getAllowedExtensions())
                .thenReturn("jpg,jpeg,png,gif,webp,pdf,txt,doc,docx,xls,xlsx");
        when(validationService.getMaxSizeBytes()).thenReturn(10485760L);
        when(uploadService.countSuccess()).thenReturn(0L);
        when(uploadService.countRejected()).thenReturn(0L);
        when(uploadService.totalStorage()).thenReturn(0L);
        when(uploadService.getAllRecords()).thenReturn(List.of());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // POST /upload
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("TC-CT-01: POST /upload file JPG hợp lệ → HTTP 200, success=true")
    void testUploadValidJpg() throws Exception {
        when(uploadService.uploadFile(any(), any())).thenReturn(successResult);

        MockMultipartFile file = new MockMultipartFile(
                "file", "photo.jpg", "image/jpeg",
                new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, 0x00}
        );

        mockMvc.perform(multipart("/upload").file(file))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value(containsString("thành công")))
                .andExpect(jsonPath("$.originalName").value("photo.jpg"))
                .andExpect(jsonPath("$.mimeType").value("image/jpeg"));
    }

    @Test
    @DisplayName("TC-CT-02: POST /upload file .php → HTTP 200, success=false, message chứa '.php'")
    void testUploadPhpFileRejected() throws Exception {
        when(uploadService.uploadFile(any(), any())).thenReturn(rejectedResult);

        MockMultipartFile file = new MockMultipartFile(
                "file", "shell.php", "application/x-php",
                "<?php ?>".getBytes()
        );

        mockMvc.perform(multipart("/upload").file(file))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value(containsString(".php")));
    }

    @Test
    @DisplayName("TC-CT-03: Response POST /upload chứa đầy đủ validation detail")
    void testUploadResponseHasValidationDetail() throws Exception {
        when(uploadService.uploadFile(any(), any())).thenReturn(successResult);

        MockMultipartFile file = new MockMultipartFile(
                "file", "photo.jpg", "image/jpeg", new byte[]{1, 2, 3}
        );

        mockMvc.perform(multipart("/upload").file(file))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.validation").exists())
                .andExpect(jsonPath("$.validation.extensionValid").value(true))
                .andExpect(jsonPath("$.validation.mimeTypeValid").value(true))
                .andExpect(jsonPath("$.validation.sizeValid").value(true))
                .andExpect(jsonPath("$.validation.nameClean").value(true))
                .andExpect(jsonPath("$.validation.detectedMimeType").value("image/jpeg"))
                .andExpect(jsonPath("$.validation.fileExtension").value("jpg"))
                .andExpect(jsonPath("$.validation.fileSizeFormatted").value("3.0 MB"));
    }

    @Test
    @DisplayName("TC-CT-04: Response rejected chứa validation detail với extensionValid=false")
    void testRejectedResponseValidationDetail() throws Exception {
        when(uploadService.uploadFile(any(), any())).thenReturn(rejectedResult);

        MockMultipartFile file = new MockMultipartFile(
                "file", "shell.php", "application/x-php", new byte[]{1}
        );

        mockMvc.perform(multipart("/upload").file(file))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.validation.extensionValid").value(false))
                .andExpect(jsonPath("$.validation.fileExtension").value("php"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /history
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("TC-CT-05: GET /history trả HTTP 200 và JSON array")
    void testHistoryEndpoint() throws Exception {
        FileRecord record = FileRecord.builder()
                .id(1L).originalName("photo.jpg").sanitizedName("photo.jpg")
                .storedName("uuid_photo.jpg").filePath("/uploads/uuid_photo.jpg")
                .fileSize(1024L).mimeType("image/jpeg").extension("jpg")
                .uploadStatus(FileRecord.UploadStatus.SUCCESS)
                .uploadedAt(LocalDateTime.now()).uploaderIp("127.0.0.1")
                .build();

        when(uploadService.getAllRecords()).thenReturn(List.of(record));

        mockMvc.perform(get("/history"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[0].originalName").value("photo.jpg"))
                .andExpect(jsonPath("$[0].uploadStatus").value("SUCCESS"));
    }

    @Test
    @DisplayName("TC-CT-06: GET /history khi rỗng trả array rỗng []")
    void testHistoryEmptyReturnsEmptyArray() throws Exception {
        when(uploadService.getAllRecords()).thenReturn(List.of());

        mockMvc.perform(get("/history"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$").isEmpty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /stats
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("TC-CT-07: GET /stats trả HTTP 200 với totalSuccess, totalRejected, totalStorage")
    void testStatsEndpoint() throws Exception {
        when(uploadService.countSuccess()).thenReturn(5L);
        when(uploadService.countRejected()).thenReturn(3L);
        when(uploadService.totalStorage()).thenReturn(5242880L); // 5MB

        mockMvc.perform(get("/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalSuccess").value(5))
                .andExpect(jsonPath("$.totalRejected").value(3))
                .andExpect(jsonPath("$.totalStorage").value("5.0 MB"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // POST /reset
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("TC-CT-08: POST /reset trả HTTP 200, success=true")
    void testResetEndpoint() throws Exception {
        mockMvc.perform(post("/reset"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value(containsString("reset")));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GET /
    // ─────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("TC-CT-09: GET / trả HTTP 200 và HTML (Thymeleaf index.html)")
    void testIndexPageReturnsHtml() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML));
    }

    @Test
    @DisplayName("TC-CT-10: POST /upload không có file → HTTP 400")
    void testUploadWithoutFileReturns400() throws Exception {
        mockMvc.perform(post("/upload")
                        .contentType(MediaType.MULTIPART_FORM_DATA))
                .andExpect(status().isBadRequest());
    }
}
