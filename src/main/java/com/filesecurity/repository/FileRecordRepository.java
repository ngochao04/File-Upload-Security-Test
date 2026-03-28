package com.filesecurity.repository;

import com.filesecurity.model.FileRecord;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FileRecordRepository extends JpaRepository<FileRecord, Long> {

    List<FileRecord> findAllByOrderByUploadedAtDesc();

    List<FileRecord> findByUploadStatus(FileRecord.UploadStatus status);

    @Query("SELECT COUNT(f) FROM FileRecord f WHERE f.uploadStatus = 'SUCCESS'")
    long countSuccessful();

    @Query("SELECT COUNT(f) FROM FileRecord f WHERE f.uploadStatus = 'REJECTED'")
    long countRejected();

    @Query("SELECT SUM(f.fileSize) FROM FileRecord f WHERE f.uploadStatus = 'SUCCESS'")
    Long totalStorageUsed();
}
