package com.filesecurity.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UploadResult {
    private boolean success;
    private String message;
    private String originalName;
    private String sanitizedName;
    private String storedName;
    private Long fileSize;
    private String mimeType;
    private String rejectionReason;
    private ValidationDetail validationDetail;

    @Data
    @Builder
    public static class ValidationDetail {
        private boolean extensionValid;
        private boolean mimeTypeValid;
        private boolean sizeValid;
        private boolean nameClean;
        private String detectedMimeType;
        private String fileExtension;
        private long fileSizeBytes;
        private String sanitizedFileName;
    }
}
