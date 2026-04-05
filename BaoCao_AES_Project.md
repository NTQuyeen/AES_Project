# BÁO CÁO ĐỒ ÁN
# MÃ HÓA VÀ GIẢI MÃ FILE DỮ LIỆU BẰNG THUẬT TOÁN AES

---

## MỤC LỤC

1. [Giới thiệu chung](#1-giới-thiệu-chung)
2. [Cơ sở lý thuyết AES](#2-cơ-sở-lý-thuyết-aes)
3. [Chi tiết thuật toán AES](#3-chi-tiết-thuật-toán-aes)
4. [So sánh AES-128 / AES-192 / AES-256](#4-so-sánh-aes-128--aes-192--aes-256)
5. [Quy trình mã hóa (Encryption)](#5-quy-trình-mã-hóa-encryption)
6. [Quy trình giải mã (Decryption)](#6-quy-trình-giải-mã-decryption)
7. [Mở rộng khóa (Key Expansion)](#7-mở-rộng-khóa-key-expansion)
8. [Xử lý file và Padding](#8-xử-lý-file-và-padding)
9. [Kiến trúc chương trình](#9-kiến-trúc-chương-trình)
10. [Giao diện người dùng (GUI)](#10-giao-diện-người-dùng-gui)
11. [Flow hoạt động tổng thể](#11-flow-hoạt-động-tổng-thể)
12. [Đo thời gian mã hóa / giải mã](#12-đo-thời-gian-mã-hóa--giải-mã)
13. [Ví dụ minh họa](#13-ví-dụ-minh-họa)

---

## 1. Giới thiệu chung

### 1.1. Đề tài
**Viết chương trình mã hóa và giải mã bằng mật mã AES.** Hỗ trợ cả 3 phiên bản AES-128, AES-192, AES-256. Mã hóa một file dữ liệu (các ký tự), cho biết thời gian mã hóa và thời gian giải mã.

### 1.2. AES là gì?
**AES (Advanced Encryption Standard)** là thuật toán mã hóa đối xứng được NIST (Viện Tiêu chuẩn và Công nghệ Quốc gia Hoa Kỳ) chọn làm tiêu chuẩn mã hóa vào năm 2001, thay thế cho DES.

- **Loại:** Mã hóa khối đối xứng (Symmetric Block Cipher)
- **Tác giả:** Joan Daemen và Vincent Rijmen (ban đầu có tên Rijndael)
- **Kích thước khối:** 128 bit (16 byte) cố định
- **Kích thước khóa:** 128 / 192 / 256 bit
- **Ứng dụng:** SSL/TLS, VPN, mã hóa ổ đĩa, WiFi WPA2...

### 1.3. Các phiên bản AES được hỗ trợ

Chương trình hỗ trợ **cả 3 phiên bản** AES:

| Thông số | AES-128 | AES-192 | AES-256 |
|---|---|---|---|
| Kích thước khóa | 128 bit (16 byte) | 192 bit (24 byte) | 256 bit (32 byte) |
| Số ký tự hex | 32 | 48 | 64 |
| Kích thước khối | 128 bit (16 byte) | 128 bit (16 byte) | 128 bit (16 byte) |
| Số vòng lặp (Rounds) | 10 | 12 | 14 |
| Nk (số word khóa) | 4 | 6 | 8 |
| Expanded Key Size | 176 byte (11×16) | 208 byte (13×16) | 240 byte (15×16) |

**Lưu ý quan trọng:** Kích thước khối luôn là **128 bit (16 byte)** cho cả 3 phiên bản. Chỉ có kích thước khóa, số vòng, và thuật toán Key Expansion khác nhau.

---

## 2. Cơ sở lý thuyết AES

### 2.1. Mã hóa đối xứng
AES là hệ mã **đối xứng**, nghĩa là dùng **cùng một khóa** cho cả mã hóa và giải mã:

```
Plaintext + Key → [AES Encrypt] → Ciphertext
Ciphertext + Key → [AES Decrypt] → Plaintext
```

**Lưu ý quan trọng:** Nếu giải mã bằng khóa khác với khóa đã mã hóa → kết quả sẽ sai hoàn toàn.

### 2.2. Mã hóa khối (Block Cipher)
AES xử lý dữ liệu theo **khối 16 byte**. Nếu dữ liệu không chia hết cho 16, cần **padding** (đệm thêm byte).

### 2.3. Ma trận State
Mỗi khối 16 byte được sắp xếp thành ma trận 4×4 (gọi là **State**), theo thứ tự **cột** (column-major):

```
Input bytes:  b0  b1  b2  b3  b4  b5  b6  b7  b8  b9  b10 b11 b12 b13 b14 b15

Ma trận State 4×4:
        Cột 0   Cột 1   Cột 2   Cột 3
Hàng 0 [ b0  ]  [ b4  ]  [ b8  ]  [ b12 ]
Hàng 1 [ b1  ]  [ b5  ]  [ b9  ]  [ b13 ]
Hàng 2 [ b2  ]  [ b6  ]  [ b10 ]  [ b14 ]
Hàng 3 [ b3  ]  [ b7  ]  [ b11 ]  [ b15 ]
```

---

## 3. Chi tiết thuật toán AES

### 3.1. Tổng quan các bước

AES thực hiện **Nr vòng (rounds)** biến đổi tùy theo kích thước khóa:
- **AES-128:** 10 vòng
- **AES-192:** 12 vòng
- **AES-256:** 14 vòng

Mỗi vòng gồm 4 phép biến đổi:

| Phép biến đổi | Tên tiếng Việt | Mục đích |
|---|---|---|
| **SubBytes** | Thay thế byte | Tạo tính phi tuyến (non-linearity) |
| **ShiftRows** | Dịch hàng | Phân tán dữ liệu theo hàng |
| **MixColumns** | Trộn cột | Phân tán dữ liệu theo cột |
| **AddRoundKey** | Cộng khóa vòng | Kết hợp khóa vào dữ liệu |

### 3.2. SubBytes — Thay thế byte

**Mục đích:** Tạo tính phi tuyến, chống lại phân tích tuyến tính (linear cryptanalysis).

**Cách hoạt động:** Mỗi byte trong State được thay thế bằng giá trị tương ứng trong **S-Box** (Substitution Box) — một bảng tra cứu 256 phần tử.

```
state[i] = S-Box[state[i]]
```

**Ví dụ:**
```
Byte đầu vào:  0x53
Tra bảng S-Box: sbox[0x53] = 0xED
Byte đầu ra:   0xED
```

**S-Box** được xây dựng từ 2 bước toán học:
1. Tính nghịch đảo nhân trong trường GF(2⁸) 
2. Áp dụng phép biến đổi affine

**Trong code** ([aes.c](file:///d:/CSATBMTT/AES_Project/src/aes.c)):
```c
void SubBytes(unsigned char state[16])
{
    for(int i = 0; i < 16; i++)
        state[i] = sbox[state[i]];  // Tra bảng S-Box
}
```

### 3.3. ShiftRows — Dịch hàng

**Mục đích:** Phân tán dữ liệu giữa các cột, đảm bảo mỗi cột sau biến đổi chứa byte từ các cột khác nhau.

**Cách hoạt động:** Dịch vòng (circular shift) các hàng của ma trận State sang **trái**:

```
Hàng 0: không dịch         (shift 0)
Hàng 1: dịch trái 1 vị trí (shift 1)
Hàng 2: dịch trái 2 vị trí (shift 2)
Hàng 3: dịch trái 3 vị trí (shift 3)
```

**Minh họa:**
```
TRƯỚC ShiftRows:          SAU ShiftRows:
[ a0  a4  a8   a12 ]      [ a0  a4  a8   a12 ]   ← Hàng 0: giữ nguyên
[ a1  a5  a9   a13 ]      [ a5  a9  a13  a1  ]   ← Hàng 1: dịch trái 1
[ a2  a6  a10  a14 ]      [ a10 a14 a2   a6  ]   ← Hàng 2: dịch trái 2
[ a3  a7  a11  a15 ]      [ a15 a3  a7   a11 ]   ← Hàng 3: dịch trái 3
```

### 3.4. MixColumns — Trộn cột

**Mục đích:** Trộn lẫn các byte trong cùng một cột, tạo tính khuếch tán (diffusion) — thay đổi 1 byte input sẽ ảnh hưởng tới nhiều byte output.

**Cách hoạt động:** Nhân mỗi cột của State với ma trận cố định trong trường Galois GF(2⁸):

```
┌          ┐   ┌             ┐   ┌          ┐
│ s'[0,c] │   │ 2  3  1  1 │   │ s[0,c]  │
│ s'[1,c] │ = │ 1  2  3  1 │ × │ s[1,c]  │
│ s'[2,c] │   │ 1  1  2  3 │   │ s[2,c]  │
│ s'[3,c] │   │ 3  1  1  2 │   │ s[3,c]  │
└          ┘   └             ┘   └          ┘
```

**Phép nhân trong GF(2⁸):**
- Nhân với **1**: giữ nguyên
- Nhân với **2**: dùng hàm `xtime()` — dịch trái 1 bit, nếu bit cao nhất là 1 thì XOR với 0x1B
- Nhân với **3**: = nhân 2 XOR giá trị gốc

**Hàm xtime** ([aes.c](file:///d:/CSATBMTT/AES_Project/src/aes.c)):
```c
unsigned char xtime(unsigned char x)
{
    return (x << 1) ^ ((x >> 7) * 0x1b);
}
```

**Lưu ý:** MixColumns **KHÔNG** được thực hiện ở vòng cuối cùng.

### 3.5. AddRoundKey — Cộng khóa vòng

**Mục đích:** Kết hợp khóa bí mật vào dữ liệu, đây là bước duy nhất sử dụng khóa.

**Cách hoạt động:** XOR từng byte của State với khóa vòng (Round Key) tương ứng.

```
state[i] = state[i] XOR roundKey[i]    (với i = 0..15)
```

**Trong code** ([aes.c](file:///d:/CSATBMTT/AES_Project/src/aes.c)):
```c
void AddRoundKey(unsigned char state[16], unsigned char roundKey[16])
{
    for(int i = 0; i < 16; i++)
        state[i] ^= roundKey[i];   // XOR
}
```

**Tính chất XOR:** `A XOR B XOR B = A` → giải mã chỉ cần XOR lại với cùng khóa.

---

## 4. So sánh AES-128 / AES-192 / AES-256

### 4.1. Bảng so sánh tổng quan

| Đặc điểm | AES-128 | AES-192 | AES-256 |
|---|---|---|---|
| **Kích thước khóa** | 128 bit (16 byte) | 192 bit (24 byte) | 256 bit (32 byte) |
| **Hex input** | 32 ký tự | 48 ký tự | 64 ký tự |
| **Số vòng (Nr)** | 10 | 12 | 14 |
| **Nk (key words)** | 4 | 6 | 8 |
| **Expanded Key** | 176 byte | 208 byte | 240 byte |
| **Round Keys** | 11 | 13 | 15 |
| **Bảo mật** | Cao | Rất cao | Cực cao |
| **Tốc độ** | Nhanh nhất | Trung bình | Chậm nhất |
| **Ứng dụng** | Đa dụng | Chính phủ | Quân sự, tài chính |

### 4.2. Điểm giống nhau (cả 3 phiên bản)

- Kích thước khối: **128 bit** (16 byte)
- Các phép biến đổi: **SubBytes, ShiftRows, MixColumns, AddRoundKey** — hoàn toàn giống nhau
- Padding: **PKCS#7** — giống nhau
- Cấu trúc vòng: Vòng đầu chỉ AddRoundKey, vòng cuối không có MixColumns

### 4.3. Điểm khác nhau chính

**1. Số vòng lặp:**
```
AES-128: 1 vòng khởi tạo + 9 vòng chính + 1 vòng cuối = 10 vòng
AES-192: 1 vòng khởi tạo + 11 vòng chính + 1 vòng cuối = 12 vòng
AES-256: 1 vòng khởi tạo + 13 vòng chính + 1 vòng cuối = 14 vòng
```

**2. Key Expansion:**
- AES-128: Modulo theo 16 byte (Nk=4)
- AES-192: Modulo theo 24 byte (Nk=6)
- AES-256: Modulo theo 32 byte (Nk=8) + **thêm bước SubWord** tại `i % 8 == 4`

**3. Bảo mật vs Tốc độ:**
- Nhiều vòng hơn = **bảo mật cao hơn** nhưng **chậm hơn**
- AES-128 đã đủ an toàn cho hầu hết ứng dụng
- AES-256 dùng khi cần bảo mật tối đa (quân sự, top-secret)

---

## 5. Quy trình mã hóa (Encryption)

### 5.1. Sơ đồ tổng thể

```
Plaintext (16 byte)
        │
        ▼
┌──────────────────┐
│  AddRoundKey(K0) │  ← Vòng 0 (Initial Round): chỉ cộng khóa
└──────────────────┘
        │
        ▼
┌──────────────────┐
│  SubBytes        │
│  ShiftRows       │  ← Vòng 1 → Nr-1 (Main Rounds): đủ 4 bước
│  MixColumns      │
│  AddRoundKey(Ki) │
└──────────────────┘
        │ (lặp Nr-1 lần: 9/11/13 lần tùy phiên bản)
        ▼
┌──────────────────┐
│  SubBytes        │
│  ShiftRows       │  ← Vòng Nr (Final Round): KHÔNG có MixColumns
│  AddRoundKey(KNr)│
└──────────────────┘
        │
        ▼
  Ciphertext (16 byte)
```

### 5.2. Code mã hóa (hỗ trợ AES-128/192/256)

**Trong code** ([aes.c](file:///d:/CSATBMTT/AES_Project/src/aes.c)):
```c
void AES_encrypt(unsigned char input[16], unsigned char output[16],
                 unsigned char *key, int keySize)
{
    unsigned char state[16];
    unsigned char expandedKey[AES_MAX_EXPANDED_KEY];  // 240 byte (max)
    int Nr = get_num_rounds(keySize);  // 10/12/14

    for(int i = 0; i < 16; i++)
        state[i] = input[i];

    KeyExpansion(key, expandedKey, keySize);

    // Vòng 0: chỉ AddRoundKey
    AddRoundKey(state, expandedKey);

    // Vòng 1 → Nr-1: SubBytes → ShiftRows → MixColumns → AddRoundKey
    for(int round = 1; round <= Nr - 1; round++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, expandedKey + (16 * round));
    }

    // Vòng Nr: SubBytes → ShiftRows → AddRoundKey (KHÔNG MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, expandedKey + (16 * Nr));

    for(int i = 0; i < 16; i++)
        output[i] = state[i];
}
```

### 5.3. Tại sao vòng cuối không có MixColumns?

Nếu thêm MixColumns ở vòng cuối, nó sẽ không tăng thêm bảo mật nhưng lại làm cấu trúc mã hóa và giải mã không đối xứng. Bỏ MixColumns ở vòng cuối giúp thuật toán có cấu trúc gọn gàng hơn khi giải mã.

---

## 6. Quy trình giải mã (Decryption)

### 6.1. Nguyên tắc

Giải mã AES thực hiện các phép biến đổi **ngược** (inverse), theo thứ tự **đảo ngược**:

| Mã hóa | Giải mã (Inverse) |
|---|---|
| SubBytes | **InvSubBytes** — dùng Inverse S-Box |
| ShiftRows | **InvShiftRows** — dịch **phải** thay vì trái |
| MixColumns | **InvMixColumns** — nhân với ma trận nghịch đảo |
| AddRoundKey | **AddRoundKey** — giữ nguyên (XOR 2 lần = trả về ban đầu) |

### 6.2. Sơ đồ giải mã

```
Ciphertext (16 byte)
        │
        ▼
┌──────────────────────┐
│  AddRoundKey(KNr)    │  ← Bắt đầu từ khóa cuối
└──────────────────────┘
        │
        ▼
┌──────────────────────┐
│  InvShiftRows        │
│  InvSubBytes         │  ← Vòng Nr-1 → 1 (ngược lại)
│  AddRoundKey(Ki)     │
│  InvMixColumns       │
└──────────────────────┘
        │ (lặp Nr-1 lần, round từ Nr-1 xuống 1)
        ▼
┌──────────────────────┐
│  InvShiftRows        │
│  InvSubBytes         │  ← Vòng cuối
│  AddRoundKey(K0)     │
└──────────────────────┘
        │
        ▼
  Plaintext (16 byte)
```

### 6.3. InvSubBytes — Thay thế byte ngược

Dùng **Inverse S-Box** (bảng tra cứu ngược 256 phần tử):

```c
void InvSubBytes(unsigned char state[16])
{
    for(int i = 0; i < 16; i++)
        state[i] = inv_sbox[state[i]];  // Tra bảng Inverse S-Box
}
```

**Tính chất:** `inv_sbox[sbox[x]] = x` (nghịch đảo hoàn toàn)

### 6.4. InvShiftRows — Dịch hàng ngược

Dịch vòng các hàng sang **phải** (ngược với ShiftRows):

```
Hàng 0: không dịch         (shift 0)
Hàng 1: dịch phải 1 vị trí
Hàng 2: dịch phải 2 vị trí
Hàng 3: dịch phải 3 vị trí
```

### 6.5. InvMixColumns — Trộn cột ngược

Nhân mỗi cột với **ma trận nghịch đảo** trong GF(2⁸):

```
┌          ┐   ┌                ┐   ┌          ┐
│ s'[0,c] │   │ 14  11  13  9  │   │ s[0,c]  │
│ s'[1,c] │ = │  9  14  11  13 │ × │ s[1,c]  │
│ s'[2,c] │   │ 13   9  14  11 │   │ s[2,c]  │
│ s'[3,c] │   │ 11  13   9  14 │   │ s[3,c]  │
└          ┘   └                ┘   └          ┘
```

### 6.6. Code giải mã (hỗ trợ AES-128/192/256)

**Trong code** ([aes.c](file:///d:/CSATBMTT/AES_Project/src/aes.c)):
```c
void AES_decrypt(unsigned char input[16], unsigned char output[16],
                 unsigned char *key, int keySize)
{
    unsigned char state[16];
    unsigned char expandedKey[AES_MAX_EXPANDED_KEY];
    int Nr = get_num_rounds(keySize);  // 10/12/14

    for(int i=0;i<16;i++)
        state[i] = input[i];

    KeyExpansion(key, expandedKey, keySize);

    // Bắt đầu từ khóa vòng cuối (KNr)
    AddRoundKey(state, expandedKey + Nr * 16);

    // Vòng Nr-1 → 1 (ngược lại)
    for(int round = Nr - 1; round >= 1; round--)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, expandedKey + round * 16);
        InvMixColumns(state);
    }

    // Vòng cuối
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, expandedKey);  // K0 (khóa gốc)

    for(int i=0;i<16;i++)
        output[i] = state[i];
}
```

---

## 7. Mở rộng khóa (Key Expansion)

### 7.1. Tại sao cần mở rộng khóa?

AES cần **(Nr + 1) round keys**, mỗi round key 16 byte:

| Phiên bản | Nr | Round Keys | Expanded Key |
|---|---|---|---|
| AES-128 | 10 | 11 | 176 byte |
| AES-192 | 12 | 13 | 208 byte |
| AES-256 | 14 | 15 | 240 byte |

### 7.2. Thuật toán Key Expansion — Tổng quát

```
Input:  Key gốc (Nk words, mỗi word 4 byte)
        Nk = 4 (AES-128) / 6 (AES-192) / 8 (AES-256)
Output: Expanded Key = (Nr+1) × 16 byte

Bước 1: Sao chép key gốc vào Nk word đầu tiên

Bước 2: Với mỗi word Wi (i ≥ Nk):
   - Nếu i % Nk == 0:
        temp = RotWord(W[i-1])
        temp = SubWord(temp)
        temp[0] ^= Rcon[i/Nk]
        W[i] = W[i-Nk] XOR temp
   - Nếu Nk == 8 VÀ i % Nk == 4:     ← CHỈ AES-256
        temp = SubWord(W[i-1])
        W[i] = W[i-Nk] XOR temp
   - Nếu không:
        W[i] = W[i-Nk] XOR W[i-1]
```

### 7.3. So sánh Key Expansion giữa 3 phiên bản

#### AES-128 (Nk=4)
```
W[i] mới tạo dựa trên W[i-4] và W[i-1]
Tại mỗi vị trí i % 4 == 0: RotWord + SubWord + Rcon
Tổng: 44 words = 176 byte
```

#### AES-192 (Nk=6)
```
W[i] mới tạo dựa trên W[i-6] và W[i-1]
Tại mỗi vị trí i % 6 == 0: RotWord + SubWord + Rcon
Tổng: 52 words = 208 byte
```

#### AES-256 (Nk=8)
```
W[i] mới tạo dựa trên W[i-8] và W[i-1]
Tại mỗi vị trí i % 8 == 0: RotWord + SubWord + Rcon
Tại mỗi vị trí i % 8 == 4: SubWord (THÊM!)  ← ĐIỂM KHÁC BIỆT QUAN TRỌNG
Tổng: 60 words = 240 byte
```

**⚠️ AES-256 có thêm bước SubWord khi i % Nk == 4 — đây là điểm khác biệt quan trọng nhất.**

### 7.4. RotWord và SubWord

```
RotWord:  [a0, a1, a2, a3] → [a1, a2, a3, a0]  (xoay vòng 1 byte)
SubWord:  Áp dụng S-Box cho từng byte trong word
```

### 7.5. Bảng Rcon (Round Constant) — Mở rộng

```
Rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]
         ↑     ↑     ↑     ↑     ↑     ↑     ↑     ↑     ↑     ↑     ↑     ↑     ↑     ↑     ↑
       skip   R1    R2    R3    R4    R5    R6    R7    R8    R9   R10   R11   R12   R13   R14
```

AES-128 dùng R1→R10, AES-192 dùng R1→R8, AES-256 dùng R1→R7.

### 7.6. Code Key Expansion (hỗ trợ cả 3 phiên bản)

**Trong code** ([aes.c](file:///d:/CSATBMTT/AES_Project/src/aes.c)):
```c
void KeyExpansion(unsigned char *key, unsigned char *expandedKey, int keySize)
{
    int Nk = keySize / 4;
    int Nr = get_num_rounds(keySize);
    int expandedKeySize = 16 * (Nr + 1);

    // Sao chép key gốc
    for(int i = 0; i < keySize; i++)
        expandedKey[i] = key[i];

    int bytesGenerated = keySize;
    int rconIteration = 1;
    unsigned char temp[4];

    while(bytesGenerated < expandedKeySize)
    {
        for(int i = 0; i < 4; i++)
            temp[i] = expandedKey[bytesGenerated - 4 + i];

        if(bytesGenerated % keySize == 0)
        {
            RotWord(temp);
            SubWord(temp);
            temp[0] ^= Rcon[rconIteration++];
        }
        // AES-256: thêm SubWord khi i % Nk == 4
        else if(Nk == 8 && (bytesGenerated % keySize) == 16)
        {
            SubWord(temp);
        }

        for(int i = 0; i < 4; i++)
        {
            expandedKey[bytesGenerated] =
                expandedKey[bytesGenerated - keySize] ^ temp[i];
            bytesGenerated++;
        }
    }
}
```

---

## 8. Xử lý file và Padding

### 8.1. Tại sao cần Padding?

AES chỉ xử lý **đúng 16 byte mỗi khối**. Nếu file không chia hết cho 16 byte, khối cuối cùng cần được **đệm thêm byte** (padding). Điều này **giống nhau cho cả 3 phiên bản AES**.

### 8.2. PKCS#7 Padding

Chương trình sử dụng chuẩn **PKCS#7**:
- Nếu thiếu `N` byte → đệm `N` byte, mỗi byte có giá trị `N`

**Ví dụ:**
```
File gốc: "Hello World!" (12 byte)
Thiếu:    16 - 12 = 4 byte
Padding:  thêm 4 byte giá trị 0x04

Kết quả:  48 65 6C 6C 6F 20 57 6F 72 6C 64 21 [04 04 04 04]
           H  e  l  l  o     W  o  r  l  d  !   ← padding →
```

### 8.3. Code Padding khi mã hóa

**Trong code** ([main.c](file:///d:/CSATBMTT/AES_Project/src/main.c)):
```c
static int encrypt_file(const char *inputFile, const char *outputFile,
                        unsigned char *key, int keySize)
{
    FILE *fin = fopen(inputFile, "rb");
    FILE *fout = fopen(outputFile, "wb");

    unsigned char buffer[16], encrypted[16];
    int bytesRead;

    while ((bytesRead = fread(buffer, 1, 16, fin)) > 0)
    {
        if (bytesRead < 16)
        {
            unsigned char pad = 16 - bytesRead;
            for (int i = bytesRead; i < 16; i++)
                buffer[i] = pad;
        }
        AES_encrypt(buffer, encrypted, key, keySize);
        fwrite(encrypted, 1, 16, fout);
    }

    fclose(fin);
    fclose(fout);
    return 0;
}
```

### 8.4. Bỏ Padding khi giải mã

**Trong code** ([main.c](file:///d:/CSATBMTT/AES_Project/src/main.c)):
```c
static int decrypt_file(const char *inputFile, const char *outputFile,
                        unsigned char *key, int keySize)
{
    FILE *fin = fopen(inputFile, "rb");
    FILE *fout = fopen(outputFile, "wb");

    unsigned char buffer[16], decrypted[16], prev[16];
    int first = 1;

    while (fread(buffer, 1, 16, fin) == 16)
    {
        AES_decrypt(buffer, decrypted, key, keySize);
        if (!first)
            fwrite(prev, 1, 16, fout);
        memcpy(prev, decrypted, 16);
        first = 0;
    }

    if (!first)
    {
        int pad = prev[15];
        if (pad >= 1 && pad <= 16)
            fwrite(prev, 1, 16 - pad, fout);
        else
            fwrite(prev, 1, 16, fout);
    }

    fclose(fin);
    fclose(fout);
    return 0;
}
```

---

## 9. Kiến trúc chương trình

### 9.1. Cấu trúc thư mục

```
AES_Project/
├── include/                     ← Headers & Lookup Tables
│   ├── aes.h                   ← Khai báo hàm AES (hỗ trợ keySize)
│   ├── aes_tables.h            ← Khai báo S-Box, Inv S-Box, Rcon
│   └── aes_tables.c            ← Bảng dữ liệu S-Box, Rcon (15 phần tử)
├── src/                         ← Source Code
│   ├── aes.c                   ← Lõi thuật toán AES-128/192/256
│   └── main.c                  ← GUI + xử lý file (encrypt/decrypt)
├── input.txt                    ← File dữ liệu test
├── encrypted.bin                ← File đã mã hóa (output)
├── decrypted.txt                ← File đã giải mã (output)
└── AES_Project.cbp              ← Project file Code::Blocks
```

### 9.2. Mối quan hệ giữa các module

```
┌────────────────────────────────────────────────────────┐
│                  main.c (GUI)                           │
│  ┌──────────────┐ ┌──────────────┐ ┌────────────────┐ │
│  │ Win32 API    │ │ File I/O     │ │ Đo thời gian   │ │
│  │ (giao diện)  │ │ (đọc/ghi)   │ │ + chọn keySize │ │
│  └──────┬───────┘ └──────┬───────┘ └────────┬───────┘ │
│         │                │                   │         │
│         └────────┬───────┘───────────────────┘         │
│                  │ Gọi AES_encrypt/AES_decrypt          │
│                  │ với tham số keySize (16/24/32)       │
└──────────────────┼─────────────────────────────────────┘
                   │
          ┌────────▼────────┐
          │    aes.c        │
          │  (AES Core)     │
          │ ┌─────────────┐ │
          │ │ SubBytes    │ │
          │ │ ShiftRows   │ │
          │ │ MixColumns  │ │───── #include ────→  aes_tables.c
          │ │ AddRoundKey │ │                      (S-Box, Rcon[15])
          │ │ KeyExpansion│ │
          │ └─────────────┘ │
          └─────────────────┘
```

### 9.3. Danh sách hàm

| File | Hàm | Mô tả |
|---|---|---|
| **aes.c** | `get_num_rounds(keySize)` | Trả về số vòng: 10/12/14 |
| | `SubBytes()` | Thay thế byte qua S-Box |
| | `ShiftRows()` | Dịch hàng trái |
| | `MixColumns()` | Trộn cột (nhân ma trận GF(2⁸)) |
| | `AddRoundKey()` | XOR state với round key |
| | `xtime()` | Nhân 2 trong GF(2⁸) |
| | `RotWord()` | Xoay vòng 4 byte |
| | `SubWord()` | SubBytes cho 1 word |
| | `KeyExpansion(key, expanded, keySize)` | Mở rộng khóa (hỗ trợ 128/192/256) |
| | `AES_encrypt(in, out, key, keySize)` | **Mã hóa 1 khối 16 byte** |
| | `InvSubBytes()` | Thay thế byte qua Inverse S-Box |
| | `InvShiftRows()` | Dịch hàng phải |
| | `InvMixColumns()` | Trộn cột ngược |
| | `gmul()` | Nhân Galois Field |
| | `AES_decrypt(in, out, key, keySize)` | **Giải mã 1 khối 16 byte** |
| **main.c** | `encrypt_file(in, out, key, keySize)` | Mã hóa toàn bộ file |
| | `decrypt_file(in, out, key, keySize)` | Giải mã toàn bộ file |
| | `hex_to_bytes(hex, bytes, numBytes)` | Chuyển chuỗi hex → byte array |
| | `generate_random_key(hexOut, keyBytes)` | Tạo khóa ngẫu nhiên (16/24/32 byte) |
| | `get_key(key, outKeySize)` | Đọc key từ UI, tự nhận diện loại |
| | `update_key_type_label()` | Cập nhật hiển thị loại khóa |
| | `WinMain()` | Entry point GUI |

---

## 10. Giao diện người dùng (GUI)

### 10.1. Công nghệ

- **Ngôn ngữ:** C thuần (không C++)
- **GUI Framework:** Win32 API (Windows native)
- **Compiler:** GCC (MinGW qua Code::Blocks)
- **Thư viện:** `gdi32` (đồ họa), `comdlg32` (dialog chọn file)

### 10.2. Bố cục giao diện

```
┌──────────────────────────────────────────────────────────┐
│              AES  Encryption / Decryption                │  ← Tiêu đề
│──────────────────────────────────────────────────────────│
│                                                           │
│  [Random Key 128-bit]  [Random Key 192-bit]  [Random Key 256-bit]  ← 3 nút Random
│                                                           │
│  Current: AES-XXX  |  Key: XXX bit  |  Rounds: XX        │  ← Thông tin loại khóa
│                                                           │
│  AES Key (XX hex characters):                             │  ← Label (tự update)
│  [____________________________________________________________]  ← Input hex key
│                                                           │
│  Input File:                                              │
│  [________________________________________] [Browse...]   │
│                                                           │
│  Original Content:                                        │
│  ┌──────────────────────────────────────────────────┐    │
│  │ (hiển thị nội dung file gốc dạng text)           │    │
│  └──────────────────────────────────────────────────┘    │
│                                                           │
│         [  ENCRYPT  ]       [  DECRYPT  ]                 │  ← 2 nút chính
│                                                           │
│  Result:                                                  │
│  ┌──────────────────────────────────────────────────┐    │
│  │ (hiển thị kết quả: hex hoặc text)                │    │
│  └──────────────────────────────────────────────────┘    │
│                                                           │
│  Encryption time: 0.000123 s (AES-XXX)  Decryption: ...  │  ← Thời gian
│  Status: Ready                                            │  ← Thanh trạng thái
└──────────────────────────────────────────────────────────┘
```

### 10.3. Mô tả các thành phần UI

| Thành phần | Loại | Chức năng |
|---|---|---|
| **Random Key 128-bit** | Button (màu vàng) | Tạo khóa ngẫu nhiên 32 ký tự hex, set mode AES-128 |
| **Random Key 192-bit** | Button (màu tím) | Tạo khóa ngẫu nhiên 48 ký tự hex, set mode AES-192 |
| **Random Key 256-bit** | Button (màu đỏ) | Tạo khóa ngẫu nhiên 64 ký tự hex, set mode AES-256 |
| **Thông tin loại khóa** | Label | Hiển thị loại AES đang dùng, kích thước khóa, số vòng |
| **AES Key** | TextBox | Nhập khóa AES dạng hex (giới hạn tự update) |
| **Input File** | TextBox (read-only) | Hiện đường dẫn file đã chọn |
| **Browse** | Button | Mở dialog chọn file Windows |
| **Original Content** | TextBox (multiline, read-only) | Hiển thị nội dung file gốc |
| **ENCRYPT** | Button (màu xanh dương) | Thực hiện mã hóa |
| **DECRYPT** | Button (màu xanh lá) | Thực hiện giải mã |
| **Result** | TextBox (multiline, read-only) | Hiển thị kết quả |
| **Encryption/Decryption time** | Label | Hiển thị thời gian + loại AES |
| **Status** | Label | Thông báo trạng thái hiện tại |

### 10.4. Cơ chế chọn loại khóa

Khi mở chương trình, **chưa có loại khóa nào được chọn**. Người dùng ấn 1 trong 3 nút Random:

1. **Random Key 128-bit** → Tạo 32 hex chars → set AES-128
2. **Random Key 192-bit** → Tạo 48 hex chars → set AES-192
3. **Random Key 256-bit** → Tạo 64 hex chars → set AES-256

Hệ thống tự nhận diện loại khóa dựa trên **độ dài chuỗi hex** khi encrypt/decrypt:
- 32 ký tự → AES-128
- 48 ký tự → AES-192
- 64 ký tự → AES-256

Người dùng cũng có thể **tự nhập khóa** thủ công với độ dài tương ứng.

---

## 11. Flow hoạt động tổng thể

### 11.1. Luồng mã hóa (Encrypt Flow)

```
                    NGƯỜI DÙNG
                        │
         ┌──────────────┼──────────────┐
         ▼              ▼              ▼
    Chọn loại khóa  Chọn File      Nhấn ENCRYPT
    (Random 128/    (Browse.txt)       │
     192/256)            │              │
         │              │              │
         └──────────────┼──────────────┘
                        │
                        ▼
              ┌─────────────────┐
              │ Kiểm tra đầu vào│  Key đủ 32/48/64 hex?
              │ + nhận diện loại│  File tồn tại?
              └────────┬────────┘
                       │ OK
                       ▼
              ┌─────────────────┐
              │  Xác định Nr    │  32 hex → Nr=10
              │  từ key length  │  48 hex → Nr=12
              │                 │  64 hex → Nr=14
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Bắt đầu đo    │  clock_t start = clock()
              │  thời gian      │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Đọc file input │  fread() 16 byte mỗi lần
              │  từng khối      │
              └────────┬────────┘
                       │
            ┌──────────▼──────────┐
            │  Khối < 16 byte?   │
            └──┬─────────────┬───┘
           CÓ  │             │ KHÔNG
               ▼             ▼
        ┌────────────┐ ┌───────────┐
        │ PKCS#7     │ │ Giữ nguyên│
        │ Padding    │ │ 16 byte   │
        └─────┬──────┘ └─────┬─────┘
              │              │
              └──────┬───────┘
                     ▼
              ┌─────────────────┐
              │  AES_encrypt()  │  Nr vòng biến đổi
              │  16 byte → 16   │  (tùy loại khóa)
              │  byte mã hóa   │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Ghi ra file    │  encrypted.bin
              │  encrypted.bin  │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Hiển thị kết  │  - Hex của encrypted.bin
              │  quả lên UI    │  - Thời gian + loại AES
              └─────────────────┘
```

### 11.2. Luồng đầy đủ từ đầu đến cuối

```
1. Mở chương trình               → GUI hiện ra, Status: "Ready — Select key type"
2. Nhấn [Random Key 256-bit]     → Key 64 hex chars, hiện "AES-256 | 256 bit | 14 rounds"
3. Nhấn [Browse] → chọn input.txt → Original Content hiện nội dung file
4. Nhấn [ENCRYPT]                → encrypted.bin được tạo
                                   → Result hiện hex data (AES-256)
                                   → Encryption time: 0.000XXX s (AES-256)
5. Nhấn [DECRYPT]                → decrypted.txt được tạo
                                   → Result hiện nội dung đã giải mã
                                   → Decryption time: 0.000XXX s (AES-256)
6. So sánh "Original Content" với "Result" → PHẢI GIỐNG NHAU
```

---

## 12. Đo thời gian mã hóa / giải mã

### 12.1. Phương pháp

Sử dụng hàm `clock()` từ thư viện `<time.h>`:

```c
clock_t start = clock();
encrypt_file("input.txt", "encrypted.bin", key, keySize);
clock_t end = clock();
double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
```

### 12.2. So sánh thời gian giữa 3 phiên bản

| Phiên bản | Số vòng | Thời gian tương đối |
|---|---|---|
| AES-128 | 10 | Nhanh nhất (baseline) |
| AES-192 | 12 | ~20% chậm hơn AES-128 |
| AES-256 | 14 | ~40% chậm hơn AES-128 |

Thời gian phụ thuộc vào: **kích thước file**, **loại khóa** (số vòng), và **tốc độ CPU**.

---

## 13. Ví dụ minh họa

### 13.1. Dữ liệu đầu vào

```
File:   input.txt
Nội dung: "toi la ngu 1231@@@@!!L::"
Kích thước: 24 byte
```

### 13.2. So sánh mã hóa cùng file với 3 loại khóa

| Bước | AES-128 | AES-192 | AES-256 |
|---|---|---|---|
| Key hex length | 32 ký tự | 48 ký tự | 64 ký tự |
| Key bytes | 16 byte | 24 byte | 32 byte |
| Rounds | 10 | 12 | 14 |
| Expanded Key | 176 byte | 208 byte | 240 byte |
| Input | 24 byte → 2 khối | 24 byte → 2 khối | 24 byte → 2 khối |
| Output (encrypted) | 32 byte | 32 byte | 32 byte |
| Decrypted | 24 byte ✅ | 24 byte ✅ | 24 byte ✅ |

**Kết quả:** Cả 3 phiên bản đều mã hóa/giải mã chính xác, khôi phục 100% dữ liệu gốc.

---

## Tóm tắt

| Đặc điểm | Chi tiết |
|---|---|
| **Thuật toán** | AES-128 / AES-192 / AES-256 (Rijndael) |
| **Loại mã hóa** | Đối xứng, mã hóa khối |
| **Kích thước khóa** | 128 / 192 / 256 bit (chọn trên GUI) |
| **Kích thước khối** | 128 bit (16 byte) — cố định |
| **Số vòng** | 10 / 12 / 14 rounds (tương ứng) |
| **Padding** | PKCS#7 |
| **Ngôn ngữ** | C |
| **Giao diện** | Win32 API (GUI Windows native) |
| **Chọn loại khóa** | 3 nút Random (128/192/256) |
| **Input** | File text bất kỳ |
| **Output** | encrypted.bin (mã hóa) + decrypted.txt (giải mã) |
| **Đo thời gian** | clock() — hiển thị microsecond |
