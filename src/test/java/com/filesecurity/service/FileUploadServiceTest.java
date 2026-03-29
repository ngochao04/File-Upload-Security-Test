package com.filesecurity.service;

import com.filesecurity.model.FileRecord;
import com.filesecurity.model.UploadResult;
import com.filesecurity.repository.FileRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit Test – FileUploadService
 *
 * Mock FileRecordRepository và FileValidationService để kiểm thử
 * FileUploadService.uploadFile() hoàn toàn cô lập.
 *
 * Chạy: mvn test -Dtest=FileUploadServiceTest
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("FileUploadService – Unit Tests")
class FileUploadServiceTest {

    @Mock
    private FileValidationService validationService;

    @Mock
    private FileRecordRepository fileRecordRepository;

    @InjectMocks
    private FileUploadService uploadService;

    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(uploadService, "uploadDir", "test-uploads");
        request = new MockHttpServletRequest();
        request.setRemoteAddr("127.0.0.1");

        // Mock save() trả về record bất kỳ
        when(fileRecordRepository.save(any(FileRecord.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    @DisplayName("TC-SV-01: File hợp lệ → upload thành công, lưu DB với status SUCCESS")
    void testValidFileUploadSuccess() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file", "photo.jpg", "image/jpeg", createFakeJpegBytes()
        );

        UploadResult.ValidationDetail detail = UploadResult.ValidationDetail.builder()
                .extensionValid(true).mimeTypeValid(true)
                .sizeValid(true).nameClean(true)
                .detectedMimeType("image/jpeg")
                .fileExtension("jpg").fileSizeBytes(20L)
                .sanitizedFileName("photo.jpg")
                .build();

        when(validationService.validate(any())).thenReturn(detail);

        UploadResult result = uploadService.uploadFile(file, request);

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getMessage()).contains("thành công");
        verify(fileRecordRepository, atLeastOnce()).save(
                argThat(r -> r.getUploadStatus() == FileRecord.UploadStatus.SUCCESS)
        );
    }

    @Test
    @DisplayName("TC-SV-02: Extension không hợp lệ → từ chối, lưu DB với status REJECTED")
    void testInvalidExtensionRejected() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file", "shell.php", "application/x-php",
                "<?php echo 'hacked'; ?>".getBytes()
        );

        UploadResult.ValidationDetail detail = UploadResult.ValidationDetail.builder()
                .extensionValid(false).mimeTypeValid(true)
                .sizeValid(true).nameClean(true)
                .detectedMimeType("application/x-php")
                .fileExtension("php").fileSizeBytes(23L)
                .sanitizedFileName("shell.php")
                .build();

        when(validationService.validate(any())).thenReturn(detail);

        UploadResult result = uploadService.uploadFile(file, request);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getMessage()).containsIgnoringCase("php");
        verify(fileRecordRepository).save(
                argThat(r -> r.getUploadStatus() == FileRecord.UploadStatus.REJECTED)
        );
    }

    @Test
    @DisplayName("TC-SV-03: File 0 byte → từ chối với thông báo 'file rỗng'")
    void testEmptyFileRejected() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file", "empty.txt", "text/plain", new byte[0]
        );

        UploadResult.ValidationDetail detail = UploadResult.ValidationDetail.builder()
                .extensionValid(true).mimeTypeValid(true)
                .sizeValid(false).nameClean(true)
                .detectedMimeType("text/plain")
                .fileExtension("txt").fileSizeBytes(0L)
                .sanitizedFileName("empty.txt")
                .build();

        when(validationService.validate(any())).thenReturn(detail);

        UploadResult result = uploadService.uploadFile(file, request);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getMessage()).containsIgnoringCase("rỗng");
    }

    @Test
    @DisplayName("TC-SV-04: File vượt 10MB → từ chối với thông báo kích thước")
    void testOversizedFileRejected() throws Exception {
        byte[] bigData = new byte[15 * 1024 * 1024]; // 15MB
        MockMultipartFile file = new MockMultipartFile(
                "file", "bigfile.jpg", "image/jpeg", bigData
        );

        UploadResult.ValidationDetail detail = UploadResult.ValidationDetail.builder()
                .extensionValid(true).mimeTypeValid(true)
                .sizeValid(false).nameClean(true)
                .detectedMimeType("image/jpeg")
                .fileExtension("jpg").fileSizeBytes(bigData.length)
                .sanitizedFileName("bigfile.jpg")
                .build();

        when(validationService.validate(any())).thenReturn(detail);

        UploadResult result = uploadService.uploadFile(file, request);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getMessage()).containsIgnoringCase("kích thước");
    }

    @Test
    @DisplayName("TC-SV-05: Tên file path traversal → từ chối với thông báo nguy hiểm")
    void testPathTraversalFileNameRejected() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file", "../../etc/passwd.jpg", "image/jpeg", createFakeJpegBytes()
        );

        UploadResult.ValidationDetail detail = UploadResult.ValidationDetail.builder()
                .extensionValid(true).mimeTypeValid(true)
                .sizeValid(true).nameClean(false)
                .detectedMimeType("image/jpeg")
                .fileExtension("jpg").fileSizeBytes(20L)
                .sanitizedFileName("passwd.jpg")
                .build();

        when(validationService.validate(any())).thenReturn(detail);

        UploadResult result = uploadService.uploadFile(file, request);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getMessage()).containsIgnoringCase("nguy hiểm");
    }

    @Test
    @DisplayName("TC-SV-06: formatSize trả đúng đơn vị B / KB / MB")
    void testFormatSize() {
        assertThat(FileUploadService.formatSize(0L)).isEqualTo("0 B");
        assertThat(FileUploadService.formatSize(512L)).isEqualTo("512 B");
        assertThat(FileUploadService.formatSize(1536L)).isEqualTo("1.5 KB");
        assertThat(FileUploadService.formatSize(5 * 1024 * 1024L)).isEqualTo("5.0 MB");
    }

    @Test
    @DisplayName("TC-SV-07: countSuccess và countRejected gọi đúng repository method")
    void testCountMethods() {
        when(fileRecordRepository.countSuccessful()).thenReturn(5L);
        when(fileRecordRepository.countRejected()).thenReturn(3L);

        assertThat(uploadService.countSuccess()).isEqualTo(5L);
        assertThat(uploadService.countRejected()).isEqualTo(3L);
    }

    @Test
    @DisplayName("TC-SV-08: totalStorage trả 0 khi repository trả null")
    void testTotalStorageHandlesNull() {
        when(fileRecordRepository.totalStorageUsed()).thenReturn(null);
        assertThat(uploadService.totalStorage()).isEqualTo(0L);
    }

    private byte[] createFakeJpegBytes() {
        return new byte[]{
                (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0,
                0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
                0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00
        };
    }
}
