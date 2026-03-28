# 🔒 SecureUpload — File Upload Security Testing

Ứng dụng web kiểm thử bảo mật upload file, xây dựng bằng **Spring Boot + PostgreSQL + Apache Tika**.

---

## 📋 Yêu cầu hệ thống

| Công cụ     | Phiên bản     |
|-------------|---------------|
| Java        | 17+           |
| Maven       | 3.8+          |
| PostgreSQL  | 14+           |

---

## ⚙️ Cài đặt & Chạy

### 1. Tạo database PostgreSQL

```sql
psql -U postgres
CREATE DATABASE file_security_db;
\q
```

Hoặc chạy file schema:
```bash
psql -U postgres -f schema.sql
```

### 2. Cấu hình database

Mở `src/main/resources/application.properties` và sửa:

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/file_security_db
spring.datasource.username=postgres
spring.datasource.password=YOUR_PASSWORD
```

### 3. Build & Run

```bash
mvn clean install
mvn spring-boot:run
```

### 4. Truy cập ứng dụng

Mở trình duyệt: **http://localhost:8080**

---

## 🛡️ Các kiểm tra bảo mật đã implement

| # | Kiểm tra | Mô tả |
|---|----------|-------|
| 1 | **Extension Whitelist** | Chỉ cho phép đuôi file trong danh sách được phép |
| 2 | **MIME Type Detection** | Dùng Apache Tika đọc magic bytes, phát hiện file giả mạo |
| 3 | **Giới hạn kích thước** | Từ chối file 0 byte và file > 10MB |
| 4 | **Path Traversal Prevention** | Chặn `../`, `..\\`, `%2e%2e` trong tên file |
| 5 | **Null Byte Injection** | Chặn `%00`, `\0` trong tên file |
| 6 | **Filename Sanitization** | Xóa ký tự đặc biệt, giới hạn độ dài tên |
| 7 | **Secure Storage** | Lưu với UUID random, ngoài web root |
| 8 | **Double Extension** | Chặn `evil.php.jpg` lấy extension cuối cùng |

---

## 📁 Cấu trúc project

```
file-upload-security/
├── pom.xml
├── schema.sql
├── uploads/                          ← Thư mục lưu file (tự tạo)
└── src/main/
    ├── java/com/filesecurity/
    │   ├── FileUploadSecurityApplication.java
    │   ├── controller/
    │   │   └── FileUploadController.java
    │   ├── service/
    │   │   ├── FileUploadService.java
    │   │   └── FileValidationService.java
    │   ├── model/
    │   │   ├── FileRecord.java
    │   │   └── UploadResult.java
    │   ├── repository/
    │   │   └── FileRecordRepository.java
    │   └── exception/
    │       └── GlobalExceptionHandler.java
    └── resources/
        ├── application.properties
        └── templates/
            └── index.html
```

---

## 🧪 Test cases gợi ý

### Test loại file
| Input | Kỳ vọng |
|-------|---------|
| `image.jpg` (ảnh thật) | ✅ PASS |
| `document.pdf` | ✅ PASS |
| `script.php` | ❌ REJECTED |
| `malware.exe` | ❌ REJECTED |
| `evil.php.jpg` (đổi tên) | ❌ REJECTED (MIME detect) |

### Test kích thước
| Input | Kỳ vọng |
|-------|---------|
| File 5MB | ✅ PASS |
| File 0 byte | ❌ REJECTED |
| File > 10MB | ❌ REJECTED |

### Test tên file
| Input | Kỳ vọng |
|-------|---------|
| `normal_file.jpg` | ✅ PASS |
| `../../etc/passwd.jpg` | ❌ REJECTED |
| `file%00.jpg` | ❌ REJECTED |
| `file<script>.jpg` | ✅ PASS (sanitized) |

---

## 📊 API Endpoints

| Method | URL | Mô tả |
|--------|-----|-------|
| GET | `/` | Trang chủ |
| POST | `/upload` | Upload file |
| GET | `/history` | Lịch sử upload (JSON) |
| GET | `/stats` | Thống kê (JSON) |
