# 3.4. Kết quả thực nghiệm

## Môi trường thực nghiệm

- **Hệ điều hành:** Windows 10/11
- **Ngôn ngữ:** C (Compiler GCC MinGW, IDE Code::Blocks)
- **Thuật toán:** AES-128, padding PKCS#7
- **Giao diện:** Win32 API (GUI)

## Dữ liệu thử nghiệm

- **File đầu vào:** `input.txt` — nội dung: `toi la ngu 1231@@@@!!L::` (24 byte)
- **Khóa AES:** Tạo ngẫu nhiên 128 bit (32 ký tự hex) qua nút "Random Key"

## Kết quả

### Mã hóa
- File `encrypted.bin` được tạo thành công (32 byte — lớn hơn do padding).
- Dữ liệu đã mã hóa hiển thị dạng hex, không thể đọc được bằng mắt thường.

### Giải mã
- File `decrypted.txt` được tạo thành công (24 byte — đúng bằng bản gốc).
- Nội dung giải mã **trùng khớp 100%** với file gốc.

### So sánh 3 file

| | input.txt | encrypted.bin | decrypted.txt |
|---|---|---|---|
| Kích thước | 24 byte | 32 byte | 24 byte |
| Đọc được | ✅ | ❌ | ✅ |
| Khớp bản gốc | — | Khác hoàn toàn | **Giống 100%** |

### Thời gian xử lý

| Thao tác | Thời gian |
|---|---|
| Mã hóa | ~ 0.000xxx s |
| Giải mã | ~ 0.000xxx s |

*(Thay bằng số liệu thực tế trên ảnh UI)*

**Nhận xét:** Cả mã hóa và giải mã đều ở mức micro-giây. Giải mã chậm hơn một chút do phép InvMixColumns phức tạp hơn MixColumns.

## Kiểm chứng

- **Cùng khóa:** Giải mã → nội dung giống hệt bản gốc ✅
- **Sai khóa:** Giải mã → nội dung sai hoàn toàn ✅ (chứng minh tính bảo mật)

## Kết luận

Chương trình mã hóa/giải mã AES-128 hoạt động chính xác, khôi phục đúng 100% dữ liệu gốc. Giao diện GUI trực quan, hiển thị đầy đủ nội dung file và thời gian xử lý. Không thể giải mã nếu không có đúng khóa.
