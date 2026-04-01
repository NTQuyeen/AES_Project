# BÁO CÁO ĐỒ ÁN
# MÃ HÓA VÀ GIẢI MÃ FILE DỮ LIỆU BẰNG THUẬT TOÁN AES-128

---

## MỤC LỤC

1. [Giới thiệu chung](#1-giới-thiệu-chung)
2. [Cơ sở lý thuyết AES](#2-cơ-sở-lý-thuyết-aes)
3. [Chi tiết thuật toán AES-128](#3-chi-tiết-thuật-toán-aes-128)
4. [Quy trình mã hóa (Encryption)](#4-quy-trình-mã-hóa-encryption)
5. [Quy trình giải mã (Decryption)](#5-quy-trình-giải-mã-decryption)
6. [Mở rộng khóa (Key Expansion)](#6-mở-rộng-khóa-key-expansion)
7. [Xử lý file và Padding](#7-xử-lý-file-và-padding)
8. [Kiến trúc chương trình](#8-kiến-trúc-chương-trình)
9. [Giao diện người dùng (GUI)](#9-giao-diện-người-dùng-gui)
10. [Flow hoạt động tổng thể](#10-flow-hoạt-động-tổng-thể)
11. [Đo thời gian mã hóa / giải mã](#11-đo-thời-gian-mã-hóa--giải-mã)
12. [Ví dụ minh họa](#12-ví-dụ-minh-họa)

---

## 1. Giới thiệu chung

### 1.1. Đề tài
**Viết chương trình mã hóa và giải mã bằng mật mã AES.** Mã hóa một file dữ liệu (các ký tự), cho biết thời gian mã hóa và thời gian giải mã.

### 1.2. AES là gì?
**AES (Advanced Encryption Standard)** là thuật toán mã hóa đối xứng được NIST (Viện Tiêu chuẩn và Công nghệ Quốc gia Hoa Kỳ) chọn làm tiêu chuẩn mã hóa vào năm 2001, thay thế cho DES.

- **Loại:** Mã hóa khối đối xứng (Symmetric Block Cipher)
- **Tác giả:** Joan Daemen và Vincent Rijmen (ban đầu có tên Rijndael)
- **Kích thước khối:** 128 bit (16 byte) cố định
- **Kích thước khóa:** 128 / 192 / 256 bit
- **Ứng dụng:** SSL/TLS, VPN, mã hóa ổ đĩa, WiFi WPA2...

### 1.3. Phiên bản sử dụng
Chương trình này sử dụng **AES-128** (khóa 128 bit = 16 byte = 32 ký tự hex).

| Thông số | Giá trị |
|---|---|
| Kích thước khối (Block Size) | 128 bit = 16 byte |
| Kích thước khóa (Key Size) | 128 bit = 16 byte |
| Số vòng lặp (Rounds) | 10 |
| Kích thước khóa mở rộng | 176 byte (11 × 16) |

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

## 3. Chi tiết thuật toán AES-128

### 3.1. Tổng quan các bước

AES-128 thực hiện **10 vòng (rounds)** biến đổi, mỗi vòng gồm 4 phép biến đổi:

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

**Trong code** ([aes.c](file:///d:/CSATBMTT/AES_Project/src/aes.c) dòng 5-9):
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

**Trong code** ([aes.c](file:///d:/CSATBMTT/AES_Project/src/aes.c) dòng 11-34):
```c
void ShiftRows(unsigned char state[16])
{
    unsigned char temp;

    // Hàng 1: dịch trái 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Hàng 2: dịch trái 2 (swap 2 cặp)
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;

    // Hàng 3: dịch trái 3 (= dịch phải 1)
    temp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}
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

**Hàm xtime** ([aes.c](file:///d:/CSATBMTT/AES_Project/src/aes.c) dòng 36-39):
```c
unsigned char xtime(unsigned char x)
{
    return (x << 1) ^ ((x >> 7) * 0x1b);
    // Nếu bit 7 = 1: (x<<1) XOR 0x1B
    // Nếu bit 7 = 0: (x<<1)
}
```

**Lưu ý:** MixColumns **KHÔNG** được thực hiện ở vòng cuối cùng (vòng 10).

### 3.5. AddRoundKey — Cộng khóa vòng

**Mục đích:** Kết hợp khóa bí mật vào dữ liệu, đây là bước duy nhất sử dụng khóa.

**Cách hoạt động:** XOR từng byte của State với khóa vòng (Round Key) tương ứng.

```
state[i] = state[i] XOR roundKey[i]    (với i = 0..15)
```

**Trong code** ([aes.c](file:///d:/CSATBMTT/AES_Project/src/aes.c) dòng 70-74):
```c
void AddRoundKey(unsigned char state[16], unsigned char roundKey[16])
{
    for(int i = 0; i < 16; i++)
        state[i] ^= roundKey[i];   // XOR
}
```

**Tính chất XOR:** `A XOR B XOR B = A` → giải mã chỉ cần XOR lại với cùng khóa.

---

## 4. Quy trình mã hóa (Encryption)

### 4.1. Sơ đồ tổng thể

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
│  ShiftRows       │  ← Vòng 1 → 9 (Main Rounds): đủ 4 bước
│  MixColumns      │
│  AddRoundKey(Ki) │
└──────────────────┘
        │ (lặp 9 lần)
        ▼
┌──────────────────┐
│  SubBytes        │
│  ShiftRows       │  ← Vòng 10 (Final Round): KHÔNG có MixColumns
│  AddRoundKey(K10)│
└──────────────────┘
        │
        ▼
  Ciphertext (16 byte)
```

### 4.2. Code mã hóa

**Trong code** ([aes.c](file:///d:/CSATBMTT/AES_Project/src/aes.c) dòng 121-147):
```c
void AES_encrypt(unsigned char input[16], unsigned char output[16], unsigned char key[16])
{
    unsigned char state[16];
    unsigned char expandedKey[176];

    // Sao chép input vào state
    for(int i = 0; i < 16; i++)
        state[i] = input[i];

    // Mở rộng khóa: 16 byte → 176 byte (11 round keys)
    KeyExpansion(key, expandedKey);

    // Vòng 0: chỉ AddRoundKey
    AddRoundKey(state, expandedKey);

    // Vòng 1 → 9: SubBytes → ShiftRows → MixColumns → AddRoundKey
    for(int round = 1; round <= 9; round++)
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, expandedKey + (16 * round));
    }

    // Vòng 10: SubBytes → ShiftRows → AddRoundKey (KHÔNG MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, expandedKey + 160);

    // Sao chép state ra output
    for(int i = 0; i < 16; i++)
        output[i] = state[i];
}
```

### 4.3. Tại sao vòng cuối không có MixColumns?

Nếu thêm MixColumns ở vòng cuối, nó sẽ không tăng thêm bảo mật nhưng lại làm cấu trúc mã hóa và giải mã không đối xứng. Bỏ MixColumns ở vòng cuối giúp thuật toán có cấu trúc gọn gàng hơn khi giải mã.

---

## 5. Quy trình giải mã (Decryption)

### 5.1. Nguyên tắc

Giải mã AES thực hiện các phép biến đổi **ngược** (inverse), theo thứ tự **đảo ngược**:

| Mã hóa | Giải mã (Inverse) |
|---|---|
| SubBytes | **InvSubBytes** — dùng Inverse S-Box |
| ShiftRows | **InvShiftRows** — dịch **phải** thay vì trái |
| MixColumns | **InvMixColumns** — nhân với ma trận nghịch đảo |
| AddRoundKey | **AddRoundKey** — giữ nguyên (XOR 2 lần = trả về ban đầu) |

### 5.2. Sơ đồ giải mã

```
Ciphertext (16 byte)
        │
        ▼
┌──────────────────────┐
│  AddRoundKey(K10)    │  ← Bắt đầu từ khóa cuối
└──────────────────────┘
        │
        ▼
┌──────────────────────┐
│  InvShiftRows        │
│  InvSubBytes         │  ← Vòng 9 → 1 (ngược lại)
│  AddRoundKey(Ki)     │
│  InvMixColumns       │
└──────────────────────┘
        │ (lặp 9 lần, round từ 9 xuống 1)
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

### 5.3. InvSubBytes — Thay thế byte ngược

Dùng **Inverse S-Box** (bảng tra cứu ngược 256 phần tử):

```c
void InvSubBytes(unsigned char state[16])
{
    for(int i = 0; i < 16; i++)
        state[i] = inv_sbox[state[i]];  // Tra bảng Inverse S-Box
}
```

**Tính chất:** `inv_sbox[sbox[x]] = x` (nghịch đảo hoàn toàn)

### 5.4. InvShiftRows — Dịch hàng ngược

Dịch vòng các hàng sang **phải** (ngược với ShiftRows):

```
Hàng 0: không dịch         (shift 0)
Hàng 1: dịch phải 1 vị trí
Hàng 2: dịch phải 2 vị trí
Hàng 3: dịch phải 3 vị trí
```

### 5.5. InvMixColumns — Trộn cột ngược

Nhân mỗi cột với **ma trận nghịch đảo** trong GF(2⁸):

```
┌          ┐   ┌                ┐   ┌          ┐
│ s'[0,c] │   │ 14  11  13  9  │   │ s[0,c]  │
│ s'[1,c] │ = │  9  14  11  13 │ × │ s[1,c]  │
│ s'[2,c] │   │ 13   9  14  11 │   │ s[2,c]  │
│ s'[3,c] │   │ 11  13   9  14 │   │ s[3,c]  │
└          ┘   └                ┘   └          ┘
```

Sử dụng hàm **gmul** (Galois Field Multiplication) để nhân trong GF(2⁸):

```c
unsigned char gmul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    for(int i = 0; i < 8; i++)
    {
        if(b & 1) p ^= a;           // Nếu bit thấp nhất của b = 1 → cộng a
        unsigned char hi = a & 0x80; // Lưu bit cao nhất
        a <<= 1;                     // Nhân a với 2
        if(hi) a ^= 0x1b;           // Nếu tràn → modulo đa thức bất khả quy
        b >>= 1;                     // Dịch b sang phải
    }
    return p;
}
```

### 5.6. Code giải mã

**Trong code** ([aes.c](file:///d:/CSATBMTT/AES_Project/src/aes.c) dòng 236-264):
```c
void AES_decrypt(unsigned char input[16], unsigned char output[16], unsigned char key[16])
{
    unsigned char state[16];
    unsigned char expandedKey[176];

    for(int i = 0; i < 16; i++)
        state[i] = input[i];

    KeyExpansion(key, expandedKey);

    // Bắt đầu từ khóa vòng cuối (K10)
    AddRoundKey(state, expandedKey + 160);

    // Vòng 9 → 1 (ngược lại)
    for(int round = 9; round >= 1; round--)
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

    for(int i = 0; i < 16; i++)
        output[i] = state[i];
}
```

---

## 6. Mở rộng khóa (Key Expansion)

### 6.1. Tại sao cần mở rộng khóa?

AES-128 có 10 vòng + 1 vòng khởi tạo = **11 round keys**, mỗi round key 16 byte.

```
Khóa gốc: 16 byte → Khóa mở rộng: 11 × 16 = 176 byte
```

### 6.2. Thuật toán Key Expansion

```
Input:  Key gốc 16 byte (4 words, mỗi word 4 byte)
Output: Expanded Key 176 byte (44 words)

Bước 1: Sao chép key gốc vào 4 word đầu tiên (W0, W1, W2, W3)

Bước 2: Với mỗi word Wi (i ≥ 4):
   - Nếu i chia hết cho 4:
        temp = W[i-1]
        temp = RotWord(temp)      ← Xoay vòng byte: [a,b,c,d] → [b,c,d,a]
        temp = SubWord(temp)      ← SubBytes cho từng byte trong word
        temp[0] ^= Rcon[i/4]     ← XOR với hằng số vòng Rcon
        W[i] = W[i-4] XOR temp
   - Nếu không:
        W[i] = W[i-4] XOR W[i-1]
```

### 6.3. RotWord và SubWord

```
RotWord:  [a0, a1, a2, a3] → [a1, a2, a3, a0]  (xoay vòng 1 byte)
SubWord:  Áp dụng S-Box cho từng byte trong word
```

### 6.4. Bảng Rcon (Round Constant)

```
Rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
         (bỏ qua) R1    R2    R3    R4    R5    R6    R7    R8    R9    R10
```

Rcon là lũy thừa của 2 trong GF(2⁸), dùng để mỗi round key khác nhau.

### 6.5. Code Key Expansion

**Trong code** ([aes.c](file:///d:/CSATBMTT/AES_Project/src/aes.c) dòng 91-119):
```c
void KeyExpansion(unsigned char key[16], unsigned char expandedKey[176])
{
    // Sao chép key gốc vào 16 byte đầu
    for(int i = 0; i < 16; i++)
        expandedKey[i] = key[i];

    int bytesGenerated = 16;
    int rconIteration = 1;
    unsigned char temp[4];

    while(bytesGenerated < 176)
    {
        // Lấy 4 byte cuối cùng đã tạo
        for(int i = 0; i < 4; i++)
            temp[i] = expandedKey[bytesGenerated - 4 + i];

        // Tại mỗi vị trí chia hết cho 16 (đầu mỗi round key)
        if(bytesGenerated % 16 == 0)
        {
            RotWord(temp);              // Xoay vòng
            SubWord(temp);              // Thay thế S-Box
            temp[0] ^= Rcon[rconIteration++]; // XOR Rcon
        }

        // XOR với word cách 16 byte trước đó
        for(int i = 0; i < 4; i++)
        {
            expandedKey[bytesGenerated] =
                expandedKey[bytesGenerated - 16] ^ temp[i];
            bytesGenerated++;
        }
    }
}
```

### 6.6. Minh họa Key Expansion

```
Key gốc:  2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C

Round Key 0 (K0):  2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C
Round Key 1 (K1):  A0 FA FE 17 88 54 2C B1 23 A3 39 39 2A 6C 76 05
Round Key 2 (K2):  F2 C2 95 F2 7A 96 B9 43 59 35 80 7A 73 59 F6 7F
...
Round Key 10 (K10): D0 14 F9 A8 C9 EE 25 89 E1 3F 0C C8 B6 63 0C A6
```

---

## 7. Xử lý file và Padding

### 7.1. Tại sao cần Padding?

AES chỉ xử lý **đúng 16 byte mỗi khối**. Nếu file không chia hết cho 16 byte, khối cuối cùng cần được **đệm thêm byte** (padding).

### 7.2. PKCS#7 Padding

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

**Trường hợp đặc biệt:**
```
Thiếu 1 byte  → thêm  01
Thiếu 2 byte  → thêm  02 02
Thiếu 3 byte  → thêm  03 03 03
...
Thiếu 15 byte → thêm  0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F 0F
```

### 7.3. Code Padding khi mã hóa

**Trong code** ([main.c](file:///d:/CSATBMTT/AES_Project/src/main.c) dòng 82-108):
```c
static int encrypt_file(const char *inputFile, const char *outputFile, unsigned char key[16])
{
    // Mở file input (binary read) và output (binary write)
    FILE *fin = fopen(inputFile, "rb");
    FILE *fout = fopen(outputFile, "wb");

    unsigned char buffer[16], encrypted[16];
    int bytesRead;

    // Đọc từng khối 16 byte
    while ((bytesRead = fread(buffer, 1, 16, fin)) > 0)
    {
        // Nếu đọc được < 16 byte → padding PKCS#7
        if (bytesRead < 16)
        {
            unsigned char pad = 16 - bytesRead;
            for (int i = bytesRead; i < 16; i++)
                buffer[i] = pad;  // Đệm giá trị = số byte thiếu
        }

        // Mã hóa AES cho khối 16 byte
        AES_encrypt(buffer, encrypted, key);

        // Ghi 16 byte đã mã hóa ra file output
        fwrite(encrypted, 1, 16, fout);
    }

    fclose(fin);
    fclose(fout);
    return 0;
}
```

### 7.4. Bỏ Padding khi giải mã

**Trong code** ([main.c](file:///d:/CSATBMTT/AES_Project/src/main.c) dòng 111-143):
```c
static int decrypt_file(const char *inputFile, const char *outputFile, unsigned char key[16])
{
    FILE *fin = fopen(inputFile, "rb");
    FILE *fout = fopen(outputFile, "wb");

    unsigned char buffer[16], decrypted[16], prev[16];
    int first = 1;

    // Đọc từng khối 16 byte
    while (fread(buffer, 1, 16, fin) == 16)
    {
        AES_decrypt(buffer, decrypted, key);

        // Ghi khối trước đó (trì hoãn 1 khối để xử lý padding ở khối cuối)
        if (!first)
            fwrite(prev, 1, 16, fout);

        memcpy(prev, decrypted, 16);
        first = 0;
    }

    // Khối cuối cùng: đọc giá trị padding
    if (!first)
    {
        int pad = prev[15];  // Byte cuối = số byte padding
        if (pad >= 1 && pad <= 16)
            fwrite(prev, 1, 16 - pad, fout);  // Ghi bỏ padding
        else
            fwrite(prev, 1, 16, fout);         // Padding không hợp lệ → ghi hết
    }

    fclose(fin);
    fclose(fout);
    return 0;
}
```

**Giải thích logic trì hoãn (deferred write):**
- Khối cuối cùng chứa padding → cần xử lý riêng
- Không biết khối nào là cuối cho đến khi đọc hết file
- → Giải pháp: luôn giữ lại khối vừa giải mã trong `prev`, chỉ ghi khi đọc được khối tiếp theo

---

## 8. Kiến trúc chương trình

### 8.1. Cấu trúc thư mục

```
AES_Project/
├── include/                     ← Headers & Lookup Tables
│   ├── aes.h                   ← Khai báo hàm AES
│   ├── aes_tables.h            ← Khai báo S-Box, Inv S-Box, Rcon
│   └── aes_tables.c            ← Bảng dữ liệu S-Box (256 phần tử)
├── src/                         ← Source Code
│   ├── aes.c                   ← Lõi thuật toán AES-128
│   └── main.c                  ← GUI + xử lý file (encrypt/decrypt)
├── input.txt                    ← File dữ liệu test
├── encrypted.bin                ← File đã mã hóa (output)
├── decrypted.txt                ← File đã giải mã (output)
└── AES_Project.cbp              ← Project file Code::Blocks
```

### 8.2. Mối quan hệ giữa các module

```
┌─────────────────────────────────────────────────┐
│                 main.c (GUI)                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────┐ │
│  │ Win32 API    │ │ File I/O     │ │ Đo thời  │ │
│  │ (giao diện)  │ │ (đọc/ghi)   │ │ gian     │ │
│  └──────┬───────┘ └──────┬───────┘ └────┬─────┘ │
│         │                │               │       │
│         └────────┬───────┘───────────────┘       │
│                  │ Gọi AES_encrypt / AES_decrypt │
└──────────────────┼───────────────────────────────┘
                   │
          ┌────────▼────────┐
          │    aes.c        │
          │  (AES Core)     │
          │ ┌─────────────┐ │
          │ │ SubBytes    │ │
          │ │ ShiftRows   │ │
          │ │ MixColumns  │ │───── #include ────→  aes_tables.c
          │ │ AddRoundKey │ │                      (S-Box, Rcon)
          │ │ KeyExpansion│ │
          │ └─────────────┘ │
          └─────────────────┘
```

### 8.3. Danh sách hàm

| File | Hàm | Mô tả |
|---|---|---|
| **aes.c** | `SubBytes()` | Thay thế byte qua S-Box |
| | `ShiftRows()` | Dịch hàng trái |
| | `MixColumns()` | Trộn cột (nhân ma trận GF(2⁸)) |
| | `AddRoundKey()` | XOR state với round key |
| | `xtime()` | Nhân 2 trong GF(2⁸) |
| | `RotWord()` | Xoay vòng 4 byte |
| | `SubWord()` | SubBytes cho 1 word |
| | `KeyExpansion()` | Mở rộng khóa 16→176 byte |
| | `AES_encrypt()` | **Mã hóa 1 khối 16 byte** |
| | `InvSubBytes()` | Thay thế byte qua Inverse S-Box |
| | `InvShiftRows()` | Dịch hàng phải |
| | `InvMixColumns()` | Trộn cột ngược |
| | `gmul()` | Nhân Galois Field |
| | `AES_decrypt()` | **Giải mã 1 khối 16 byte** |
| **main.c** | `encrypt_file()` | Mã hóa toàn bộ file (nhiều khối) |
| | `decrypt_file()` | Giải mã toàn bộ file |
| | `hex_to_bytes()` | Chuyển chuỗi hex → byte array |
| | `generate_random_key()` | Tạo khóa ngẫu nhiên |
| | `WinMain()` | Entry point GUI |

---

## 9. Giao diện người dùng (GUI)

### 9.1. Công nghệ

- **Ngôn ngữ:** C thuần (không C++)
- **GUI Framework:** Win32 API (Windows native)
- **Compiler:** GCC (MinGW qua Code::Blocks)
- **Thư viện:** `gdi32` (đồ họa), `comdlg32` (dialog chọn file)

### 9.2. Bố cục giao diện

```
┌──────────────────────────────────────────────────────┐
│            AES-128 Encryption / Decryption            │  ← Tiêu đề
│──────────────────────────────────────────────────────│
│                                                       │
│  AES Key (32 hex characters):                         │  ← Label
│  [________________________] [Random Key]              │  ← Input + Button
│                                                       │
│  Input File:                                          │  ← Label
│  [________________________] [Browse...]               │  ← Input + Button
│                                                       │
│  Original Content:                                    │  ← Label
│  ┌──────────────────────────────────────────────┐    │
│  │ (hiển thị nội dung file gốc dạng text)       │    │  ← TextBox (read-only)
│  └──────────────────────────────────────────────┘    │
│                                                       │
│         [  ENCRYPT  ]       [  DECRYPT  ]             │  ← 2 nút chính
│                                                       │
│  Result:                                              │  ← Label
│  ┌──────────────────────────────────────────────┐    │
│  │ (hiển thị kết quả: hex hoặc text)            │    │  ← TextBox (read-only)
│  └──────────────────────────────────────────────┘    │
│                                                       │
│  Encryption time: 0.000123 s   Decryption time: ...   │  ← Thời gian
│  Status: Ready                                        │  ← Thanh trạng thái
└──────────────────────────────────────────────────────┘
```

### 9.3. Mô tả các thành phần UI

| Thành phần | Loại | Chức năng |
|---|---|---|
| **AES Key** | TextBox + giới hạn 32 ký tự | Nhập khóa AES dạng hex (VD: `2B7E151628AED2A6ABF7158809CF4F3C`) |
| **Random Key** | Button | Tạo ngẫu nhiên 32 ký tự hex |
| **Input File** | TextBox (read-only) | Hiện đường dẫn file đã chọn |
| **Browse** | Button | Mở dialog chọn file Windows |
| **Original Content** | TextBox (multiline, read-only) | Hiển thị nội dung file gốc |
| **ENCRYPT** | Button | Thực hiện mã hóa |
| **DECRYPT** | Button | Thực hiện giải mã |
| **Result** | TextBox (multiline, read-only) | Hiển thị kết quả (hex nếu encrypt, text nếu decrypt) |
| **Encryption time** | Label | Hiển thị thời gian mã hóa (giây) |
| **Decryption time** | Label | Hiển thị thời gian giải mã (giây) |
| **Status** | Label | Thông báo trạng thái hiện tại |

### 9.4. Khóa AES (Key)

**Đầu vào:** 32 ký tự hexadecimal (0-9, A-F)

**Chuyển đổi:** Mỗi 2 ký tự hex → 1 byte → tổng cộng 16 byte

```
Hex input:  "2B7E151628AED2A6ABF7158809CF4F3C"

Chuyển đổi:
  "2B" → 0x2B (43)     "7E" → 0x7E (126)
  "15" → 0x15 (21)     "16" → 0x16 (22)
  "28" → 0x28 (40)     "AE" → 0xAE (174)
  "D2" → 0xD2 (210)    "A6" → 0xA6 (166)
  "AB" → 0xAB (171)    "F7" → 0xF7 (247)
  "15" → 0x15 (21)     "88" → 0x88 (136)
  "09" → 0x09 (9)      "CF" → 0xCF (207)
  "4F" → 0x4F (79)     "3C" → 0x3C (60)

Key 16 byte: [2B, 7E, 15, 16, 28, AE, D2, A6, AB, F7, 15, 88, 09, CF, 4F, 3C]
```

---

## 10. Flow hoạt động tổng thể

### 10.1. Luồng mã hóa (Encrypt Flow)

```
                    NGƯỜI DÙNG
                        │
         ┌──────────────┼──────────────┐
         ▼              ▼              ▼
    Nhập Key       Chọn File      Nhấn ENCRYPT
    (32 hex)     (Browse.txt)         │
         │              │              │
         └──────────────┼──────────────┘
                        │
                        ▼
              ┌─────────────────┐
              │ Kiểm tra đầu vào│  Key đủ 32 hex?
              │                 │  File tồn tại?
              └────────┬────────┘
                       │ OK
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
              │  AES_encrypt()  │  10 vòng biến đổi
              │  16 byte → 16   │
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
              │  Kết thúc đo   │  clock_t end = clock()
              │  thời gian     │  time = (end-start)/CLOCKS_PER_SEC
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Hiển thị kết  │  - Hex của encrypted.bin
              │  quả lên UI    │  - Thời gian mã hóa
              └─────────────────┘
```

### 10.2. Luồng giải mã (Decrypt Flow)

```
                    NGƯỜI DÙNG
                        │
                   Nhấn DECRYPT
                        │
                        ▼
              ┌─────────────────┐
              │ Kiểm tra:       │  encrypted.bin tồn tại?
              │ Key đúng?       │  Key giống lúc encrypt?
              └────────┬────────┘
                       │ OK
                       ▼
              ┌─────────────────┐
              │  Bắt đầu đo    │  clock_t start = clock()
              │  thời gian      │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Đọc file       │  fread() 16 byte mỗi lần
              │  encrypted.bin  │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  AES_decrypt()  │  10 vòng biến đổi ngược
              │  16 byte → 16   │
              │  byte gốc       │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ Khối cuối cùng? │
              └──┬──────────┬───┘
             CÓ  │          │ KHÔNG
                 ▼          ▼
          ┌────────────┐  ┌──────────┐
          │ Bỏ padding │  │ Ghi đủ   │
          │ PKCS#7     │  │ 16 byte  │
          └─────┬──────┘  └────┬─────┘
                │              │
                └──────┬───────┘
                       ▼
              ┌─────────────────┐
              │  Ghi ra file    │  decrypted.txt
              │  decrypted.txt  │
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │  Kết thúc đo,  │  - Nội dung decrypted.txt
              │  hiển thị UI   │  - Thời gian giải mã
              └─────────────────┘
```

### 10.3. Luồng đầy đủ từ đầu đến cuối

```
1. Mở chương trình                → GUI hiện ra, Status: "Ready"
2. Nhấn [Random Key]              → Key ngẫu nhiên: VD "A3F2B8C1D4E5F6789012345678ABCDEF"
3. Nhấn [Browse] → chọn input.txt → Original Content hiện nội dung file
4. Nhấn [ENCRYPT]                 → encrypted.bin được tạo cùng thư mục
                                   → Result hiện hex data
                                   → Encryption time: 0.000XXX s
5. Nhấn [DECRYPT]                 → decrypted.txt được tạo cùng thư mục
                                   → Result hiện nội dung đã giải mã
                                   → Decryption time: 0.000XXX s
6. So sánh "Original Content" với "Result" (sau decrypt) → PHẢI GIỐNG NHAU
```

---

## 11. Đo thời gian mã hóa / giải mã

### 11.1. Phương pháp

Sử dụng hàm `clock()` từ thư viện `<time.h>`:

```c
clock_t start = clock();          // Bắt đầu đo

encrypt_file("input.txt", "encrypted.bin", key);  // Thực hiện mã hóa

clock_t end = clock();            // Kết thúc đo

double elapsed = (double)(end - start) / CLOCKS_PER_SEC;  // Tính thời gian (giây)
```

### 11.2. Ý nghĩa

- **CLOCKS_PER_SEC**: Số "clock ticks" trong 1 giây (thường = 1000 trên Windows)
- Thời gian tính bằng **giây**, hiện thị 6 chữ số thập phân (microsecond)
- Thời gian phụ thuộc vào: **kích thước file** (nhiều khối → lâu hơn) và **tốc độ CPU**

### 11.3. Kết quả mẫu

```
File kích thước 24 byte (2 khối AES):
   Encryption time: 0.000012 s
   Decryption time: 0.000008 s

File kích thước 1 MB (~65536 khối):
   Encryption time: 0.125000 s
   Decryption time: 0.118000 s
```

---

## 12. Ví dụ minh họa

### 12.1. Dữ liệu đầu vào

```
File:   input.txt
Nội dung: "toi la ngu 1231@@@@!!L::"
Kích thước: 24 byte
```

### 12.2. Khóa AES

```
Key (hex): 2B7E151628AED2A6ABF7158809CF4F3C
Key (byte): [2B, 7E, 15, 16, 28, AE, D2, A6, AB, F7, 15, 88, 09, CF, 4F, 3C]
```

### 12.3. Quá trình mã hóa

```
Bước 1: Đọc file → 24 byte
        "toi la ngu 1231@@@@!!L::"

Bước 2: Chia thành khối 16 byte
        Khối 1: "toi la ngu 1231@"  (16 byte, đủ 16)
        Khối 2: "@@@!!L::"          (8 byte, cần padding)

Bước 3: Padding PKCS#7 cho khối 2
        Thiếu: 16 - 8 = 8 byte → đệm 8 byte giá trị 0x08
        Khối 2 sau padding: "@@@!!L::" + [08 08 08 08 08 08 08 08]

Bước 4: Mã hóa AES từng khối
        Khối 1 → AES_encrypt() → 16 byte ciphertext
        Khối 2 → AES_encrypt() → 16 byte ciphertext

Bước 5: Ghi 32 byte ra encrypted.bin
```

### 12.4. Quá trình giải mã

```
Bước 1: Đọc encrypted.bin → 32 byte (2 khối)

Bước 2: Giải mã AES từng khối
        Khối 1 → AES_decrypt() → "toi la ngu 1231@"  (16 byte)
        Khối 2 → AES_decrypt() → "@@@!!L::" + [08 08 08 08 08 08 08 08]

Bước 3: Khối 1: ghi đủ 16 byte ra file

Bước 4: Khối 2 (khối cuối): đọc padding
        Byte cuối = 0x08 → padding = 8 byte
        Ghi 16 - 8 = 8 byte → "@@@!!L::"

Bước 5: File decrypted.txt = "toi la ngu 1231@@@@!!L::"

Kết quả: GIỐNG HỆT file gốc ✅
```

---

## Tóm tắt

| Đặc điểm | Chi tiết |
|---|---|
| **Thuật toán** | AES-128 (Rijndael) |
| **Loại mã hóa** | Đối xứng, mã hóa khối |
| **Kích thước khóa** | 128 bit (32 ký tự hex) |
| **Kích thước khối** | 128 bit (16 byte) |
| **Số vòng** | 10 rounds |
| **Padding** | PKCS#7 |
| **Ngôn ngữ** | C |
| **Giao diện** | Win32 API (GUI Windows native) |
| **Input** | File text bất kỳ |
| **Output** | encrypted.bin (mã hóa) + decrypted.txt (giải mã) |
| **Đo thời gian** | clock() — hiển thị microsecond |
