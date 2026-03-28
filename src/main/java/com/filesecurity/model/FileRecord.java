package com.filesecurity.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;

@Entity
@Table(name = "file_records")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FileRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "original_name", nullable = false)
    private String originalName;

    @Column(name = "sanitized_name", nullable = false)
    private String sanitizedName;

    @Column(name = "stored_name", nullable = false, unique = true)
    private String storedName;

    @Column(name = "file_path", nullable = false)
    private String filePath;

    @Column(name = "file_size", nullable = false)
    private Long fileSize;

    @Column(name = "mime_type", nullable = false)
    private String mimeType;

    @Column(name = "extension")
    private String extension;

    @Column(name = "upload_status", nullable = false)
    @Enumerated(EnumType.STRING)
    private UploadStatus uploadStatus;

    @Column(name = "rejection_reason")
    private String rejectionReason;

    @Column(name = "uploaded_at", nullable = false)
    private LocalDateTime uploadedAt;

    @Column(name = "uploader_ip")
    private String uploaderIp;

    public enum UploadStatus {
        SUCCESS, REJECTED, QUARANTINED
    }
}
