# CI/CD Secrets Leak Sentinel

Hệ thống giám sát, phát hiện và tự động ứng phó sự cố rò rỉ thông tin bí mật (API Keys, Tokens, Private Keys) trong chuỗi cung ứng CI/CD.

## Tính năng chính

* **Hybrid Scanner Engine:** Kết hợp Biểu thức chính quy (Regex) và Độ hỗn loạn Shannon (Shannon Entropy).

* **De-obfuscator Module:** Tự động giải mã các kỹ thuật né tránh (Base64, Hex, Unicode Escape).

* **Auto-Remediation (Mở rộng):** Tự động thu hồi khóa bị lộ (Auto-Revocation) và tạo Pull Request nâng cấp thư viện dính CVE (Auto-Patching).

## Kết quả Thực nghiệm (10.000 mẫu)

* **Precision:** `100.00%` | **Recall:** `87.28%` | **F1-Score:** `93.21%`

* **Độ trễ trung bình:** `0.0231 ms/mẫu`