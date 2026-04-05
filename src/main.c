#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "aes.h"

/* ======================== CONSTANTS ======================== */
#define WIN_WIDTH   820
#define WIN_HEIGHT  760

#define ID_BTN_BROWSE       1001
#define ID_BTN_ENCRYPT      1002
#define ID_BTN_DECRYPT      1003
#define ID_BTN_RANDOM_128   1004
#define ID_BTN_RANDOM_192   1005
#define ID_BTN_RANDOM_256   1006
#define ID_EDIT_KEY         1007
#define ID_EDIT_FILEPATH    1008
#define ID_EDIT_ORIGINAL    1009
#define ID_EDIT_RESULT      1010
#define ID_STATIC_TIME_ENC  1011
#define ID_STATIC_TIME_DEC  1012
#define ID_STATIC_STATUS    1013
#define ID_STATIC_KEYTYPE   1014

/* ======================== COLORS ======================== */
#define CLR_BG          RGB(30, 30, 46)
#define CLR_SURFACE     RGB(45, 45, 65)
#define CLR_ACCENT      RGB(137, 180, 250)
#define CLR_ACCENT2     RGB(166, 227, 161)
#define CLR_ACCENT3     RGB(249, 226, 175)
#define CLR_RED         RGB(243, 139, 168)
#define CLR_PURPLE      RGB(203, 166, 247)
#define CLR_TEXT        RGB(205, 214, 244)
#define CLR_SUBTEXT    RGB(147, 153, 178)
#define CLR_INPUT_BG   RGB(49, 50, 68)
#define CLR_BORDER     RGB(88, 91, 112)

/* ======================== GLOBALS ======================== */
static HWND hEditKey, hEditFilePath;
static HWND hEditOriginal, hEditResult;
static HWND hBtnBrowse, hBtnEncrypt, hBtnDecrypt;
static HWND hBtnRandom128, hBtnRandom192, hBtnRandom256;
static HWND hStaticTimeEnc, hStaticTimeDec, hStaticStatus;
static HWND hStaticKeyType;
static HWND hLabelKey, hLabelFile, hLabelOriginal, hLabelResult;
static HWND hTitle;

static HBRUSH hBrBg, hBrSurface, hBrInput;
static HFONT hFontTitle, hFontLabel, hFontNormal, hFontMono, hFontBtn;

static char g_inputPath[MAX_PATH] = {0};
static char g_encPath[MAX_PATH]   = {0};
static char g_decPath[MAX_PATH]   = {0};

/* Current key size: 0 = not selected, 16 = AES-128, 24 = AES-192, 32 = AES-256 */
static int g_keySize = 0;

/* ======================== HEX HELPERS ======================== */
static void hex_to_bytes(const char *hex, unsigned char *bytes, int numBytes)
{
    for (int i = 0; i < numBytes; i++)
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
}

static void bytes_to_hex(const unsigned char *bytes, int len, char *out)
{
    for (int i = 0; i < len; i++)
        sprintf(out + i * 3, "%02X ", bytes[i]);
    if (len > 0) out[len * 3 - 1] = '\0';
}

/* ======================== BUILD OUTPUT PATHS ======================== */
static void build_output_paths(const char *inputPath)
{
    char dir[MAX_PATH] = {0};
    strcpy(dir, inputPath);
    char *lastSlash = strrchr(dir, '\\');
    if (!lastSlash) lastSlash = strrchr(dir, '/');
    if (lastSlash) *(lastSlash + 1) = '\0';
    else strcpy(dir, ".\\");

    sprintf(g_encPath, "%sencrypted.bin", dir);
    sprintf(g_decPath, "%sdecrypted.txt", dir);
}

/* ================== ENCRYPT FILE ================== */
static int encrypt_file(const char *inputFile, const char *outputFile,
                        unsigned char *key, int keySize)
{
    FILE *fin = fopen(inputFile, "rb");
    if (!fin) return -1;

    FILE *fout = fopen(outputFile, "wb");
    if (!fout) { fclose(fin); return -2; }

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

/* ================== DECRYPT FILE ================== */
static int decrypt_file(const char *inputFile, const char *outputFile,
                        unsigned char *key, int keySize)
{
    FILE *fin = fopen(inputFile, "rb");
    if (!fin) return -1;

    FILE *fout = fopen(outputFile, "wb");
    if (!fout) { fclose(fin); return -2; }

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

/* ================== READ FILE TO STRING ================== */
static char *read_file_text(const char *path, long *outLen)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    long readLen = (len > 4096) ? 4096 : len;
    char *buf = (char *)malloc(readLen + 64);
    if (!buf) { fclose(f); return NULL; }

    fread(buf, 1, readLen, f);
    fclose(f);

    if (len > 4096)
    {
        sprintf(buf + readLen, "\r\n... [truncated, %ld bytes total]", len);
        readLen = (long)strlen(buf);
    }
    else
    {
        buf[readLen] = '\0';
    }

    if (outLen) *outLen = readLen;
    return buf;
}

/* ================== READ BINARY FILE AS HEX ================== */
static char *read_file_hex(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    long readLen = (len > 1024) ? 1024 : len;
    unsigned char *raw = (unsigned char *)malloc(readLen);
    if (!raw) { fclose(f); return NULL; }
    fread(raw, 1, readLen, f);
    fclose(f);

    char *hex = (char *)malloc(readLen * 4 + 256);
    if (!hex) { free(raw); return NULL; }

    int pos = 0;
    for (long i = 0; i < readLen; i++)
    {
        pos += sprintf(hex + pos, "%02X ", raw[i]);
        if ((i + 1) % 16 == 0)
            pos += sprintf(hex + pos, "\r\n");
    }

    if (len > 1024)
        pos += sprintf(hex + pos, "\r\n... [truncated, %ld bytes total]", len);

    hex[pos] = '\0';
    free(raw);
    return hex;
}

/* ================== GENERATE RANDOM KEY ================== */
static void generate_random_key(char *hexOut, int keyBytes)
{
    srand((unsigned)time(NULL) ^ (unsigned)GetTickCount());
    for (int i = 0; i < keyBytes; i++)
    {
        unsigned char b = (unsigned char)(rand() & 0xFF);
        sprintf(hexOut + i * 2, "%02X", b);
    }
    hexOut[keyBytes * 2] = '\0';
}

/* ================== UPDATE KEY TYPE DISPLAY ================== */
static void update_key_type_label(void)
{
    char label[128];
    char keyLabel[128];

    if (g_keySize == 16)
    {
        sprintf(label, "  Current: AES-128  |  Key: 128 bit  |  Rounds: 10");
        sprintf(keyLabel, "AES Key (32 hex characters):");
        SendMessage(hEditKey, EM_SETLIMITTEXT, 32, 0);
    }
    else if (g_keySize == 24)
    {
        sprintf(label, "  Current: AES-192  |  Key: 192 bit  |  Rounds: 12");
        sprintf(keyLabel, "AES Key (48 hex characters):");
        SendMessage(hEditKey, EM_SETLIMITTEXT, 48, 0);
    }
    else if (g_keySize == 32)
    {
        sprintf(label, "  Current: AES-256  |  Key: 256 bit  |  Rounds: 14");
        sprintf(keyLabel, "AES Key (64 hex characters):");
        SendMessage(hEditKey, EM_SETLIMITTEXT, 64, 0);
    }
    else
    {
        sprintf(label, "  Please select a key type by clicking a Random button below");
        sprintf(keyLabel, "AES Key:");
        SendMessage(hEditKey, EM_SETLIMITTEXT, 64, 0);
    }

    SetWindowText(hStaticKeyType, label);
    SetWindowText(hLabelKey, keyLabel);
}

/* ================== CREATE FONTS ================== */
static void create_fonts(void)
{
    hFontTitle = CreateFont(28, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    hFontLabel = CreateFont(16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    hFontNormal = CreateFont(15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");

    hFontMono = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");

    hFontBtn = CreateFont(15, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Segoe UI");
}

/* ================== CUSTOM BUTTON DRAW ================== */
static void draw_button(LPDRAWITEMSTRUCT dis)
{
    COLORREF bgColor, textColor;
    int id = dis->CtlID;

    if (id == ID_BTN_ENCRYPT)          { bgColor = CLR_ACCENT;  textColor = RGB(30,30,46); }
    else if (id == ID_BTN_DECRYPT)     { bgColor = CLR_ACCENT2; textColor = RGB(30,30,46); }
    else if (id == ID_BTN_RANDOM_128)  { bgColor = CLR_ACCENT3; textColor = RGB(30,30,46); }
    else if (id == ID_BTN_RANDOM_192)  { bgColor = CLR_PURPLE;  textColor = RGB(30,30,46); }
    else if (id == ID_BTN_RANDOM_256)  { bgColor = CLR_RED;     textColor = RGB(30,30,46); }
    else                               { bgColor = CLR_SURFACE;  textColor = CLR_TEXT; }

    /* Hover effect */
    if (dis->itemState & ODS_SELECTED)
    {
        bgColor = RGB(
            GetRValue(bgColor) * 80 / 100,
            GetGValue(bgColor) * 80 / 100,
            GetBValue(bgColor) * 80 / 100
        );
    }

    /* Draw rounded rect */
    HBRUSH hBr = CreateSolidBrush(bgColor);
    HPEN hPen = CreatePen(PS_SOLID, 1, bgColor);
    SelectObject(dis->hDC, hBr);
    SelectObject(dis->hDC, hPen);
    RoundRect(dis->hDC, dis->rcItem.left, dis->rcItem.top,
              dis->rcItem.right, dis->rcItem.bottom, 12, 12);

    /* Draw text */
    SetBkMode(dis->hDC, TRANSPARENT);
    SetTextColor(dis->hDC, textColor);
    SelectObject(dis->hDC, hFontBtn);

    char text[64];
    GetWindowText(dis->hwndItem, text, sizeof(text));
    DrawText(dis->hDC, text, -1, &dis->rcItem,
             DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    DeleteObject(hBr);
    DeleteObject(hPen);
}

/* ================== CREATE CONTROLS ================== */
static void create_controls(HWND hwnd)
{
    int leftMargin = 30;
    int contentW = WIN_WIDTH - 60;
    int y = 20;

    /* Title */
    hTitle = CreateWindow("STATIC",
        "  AES  Encryption / Decryption",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        leftMargin, y, contentW, 36,
        hwnd, NULL, NULL, NULL);
    SendMessage(hTitle, WM_SETFONT, (WPARAM)hFontTitle, TRUE);
    y += 50;

    /* === 3 Random Key Buttons === */
    {
        int btnW = 220;
        int gap = 15;
        int totalW = btnW * 3 + gap * 2;
        int startX = (WIN_WIDTH - totalW) / 2;

        hBtnRandom128 = CreateWindow("BUTTON", "Random Key 128-bit",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            startX, y, btnW, 34,
            hwnd, (HMENU)ID_BTN_RANDOM_128, NULL, NULL);

        hBtnRandom192 = CreateWindow("BUTTON", "Random Key 192-bit",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            startX + btnW + gap, y, btnW, 34,
            hwnd, (HMENU)ID_BTN_RANDOM_192, NULL, NULL);

        hBtnRandom256 = CreateWindow("BUTTON", "Random Key 256-bit",
            WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
            startX + (btnW + gap) * 2, y, btnW, 34,
            hwnd, (HMENU)ID_BTN_RANDOM_256, NULL, NULL);
    }
    y += 44;

    /* Key type info label */
    hStaticKeyType = CreateWindow("STATIC",
        "  Please select a key type by clicking a Random button above",
        WS_CHILD | WS_VISIBLE,
        leftMargin, y, contentW, 22,
        hwnd, (HMENU)ID_STATIC_KEYTYPE, NULL, NULL);
    SendMessage(hStaticKeyType, WM_SETFONT, (WPARAM)hFontNormal, TRUE);
    y += 30;

    /* Key label */
    hLabelKey = CreateWindow("STATIC", "AES Key:",
        WS_CHILD | WS_VISIBLE,
        leftMargin, y, 300, 20,
        hwnd, NULL, NULL, NULL);
    SendMessage(hLabelKey, WM_SETFONT, (WPARAM)hFontLabel, TRUE);
    y += 24;

    /* Key input */
    hEditKey = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_UPPERCASE,
        leftMargin, y, contentW, 30,
        hwnd, (HMENU)ID_EDIT_KEY, NULL, NULL);
    SendMessage(hEditKey, WM_SETFONT, (WPARAM)hFontMono, TRUE);
    SendMessage(hEditKey, EM_SETLIMITTEXT, 64, 0);
    y += 44;

    /* File label */
    hLabelFile = CreateWindow("STATIC", "Input File:",
        WS_CHILD | WS_VISIBLE,
        leftMargin, y, 100, 20,
        hwnd, NULL, NULL, NULL);
    SendMessage(hLabelFile, WM_SETFONT, (WPARAM)hFontLabel, TRUE);
    y += 24;

    /* File path input */
    hEditFilePath = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY,
        leftMargin, y, contentW - 120, 30,
        hwnd, (HMENU)ID_EDIT_FILEPATH, NULL, NULL);
    SendMessage(hEditFilePath, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

    /* Browse button */
    hBtnBrowse = CreateWindow("BUTTON", "Browse...",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        leftMargin + contentW - 110, y, 110, 30,
        hwnd, (HMENU)ID_BTN_BROWSE, NULL, NULL);
    y += 44;

    /* Original content label */
    hLabelOriginal = CreateWindow("STATIC", "Original Content:",
        WS_CHILD | WS_VISIBLE,
        leftMargin, y, 200, 20,
        hwnd, NULL, NULL, NULL);
    SendMessage(hLabelOriginal, WM_SETFONT, (WPARAM)hFontLabel, TRUE);
    y += 22;

    /* Original content textbox */
    hEditOriginal = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        leftMargin, y, contentW, 90,
        hwnd, (HMENU)ID_EDIT_ORIGINAL, NULL, NULL);
    SendMessage(hEditOriginal, WM_SETFONT, (WPARAM)hFontMono, TRUE);
    y += 100;

    /* Buttons row */
    int btnW = 180;
    int gap = 30;
    int totalBtnW = btnW * 2 + gap;
    int btnX = (WIN_WIDTH - totalBtnW) / 2;

    hBtnEncrypt = CreateWindow("BUTTON", "ENCRYPT",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        btnX, y, btnW, 42,
        hwnd, (HMENU)ID_BTN_ENCRYPT, NULL, NULL);

    hBtnDecrypt = CreateWindow("BUTTON", "DECRYPT",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        btnX + btnW + gap, y, btnW, 42,
        hwnd, (HMENU)ID_BTN_DECRYPT, NULL, NULL);
    y += 56;

    /* Result label */
    hLabelResult = CreateWindow("STATIC", "Result:",
        WS_CHILD | WS_VISIBLE,
        leftMargin, y, 200, 20,
        hwnd, NULL, NULL, NULL);
    SendMessage(hLabelResult, WM_SETFONT, (WPARAM)hFontLabel, TRUE);
    y += 22;

    /* Result textbox */
    hEditResult = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        leftMargin, y, contentW, 90,
        hwnd, (HMENU)ID_EDIT_RESULT, NULL, NULL);
    SendMessage(hEditResult, WM_SETFONT, (WPARAM)hFontMono, TRUE);
    y += 100;

    /* Time labels */
    hStaticTimeEnc = CreateWindow("STATIC", "Encryption time:  --",
        WS_CHILD | WS_VISIBLE,
        leftMargin, y, contentW / 2, 22,
        hwnd, (HMENU)ID_STATIC_TIME_ENC, NULL, NULL);
    SendMessage(hStaticTimeEnc, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

    hStaticTimeDec = CreateWindow("STATIC", "Decryption time:  --",
        WS_CHILD | WS_VISIBLE,
        leftMargin + contentW / 2, y, contentW / 2, 22,
        hwnd, (HMENU)ID_STATIC_TIME_DEC, NULL, NULL);
    SendMessage(hStaticTimeDec, WM_SETFONT, (WPARAM)hFontNormal, TRUE);
    y += 30;

    /* Status */
    hStaticStatus = CreateWindow("STATIC", "Status: Ready — Select key type to begin",
        WS_CHILD | WS_VISIBLE,
        leftMargin, y, contentW, 22,
        hwnd, (HMENU)ID_STATIC_STATUS, NULL, NULL);
    SendMessage(hStaticStatus, WM_SETFONT, (WPARAM)hFontLabel, TRUE);
}

/* ================== BROWSE FILE ================== */
static void do_browse(HWND hwnd)
{
    OPENFILENAME ofn;
    char szFile[MAX_PATH] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = "Text Files (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn))
    {
        strcpy(g_inputPath, szFile);
        SetWindowText(hEditFilePath, szFile);
        build_output_paths(szFile);

        long len = 0;
        char *content = read_file_text(szFile, &len);
        if (content)
        {
            SetWindowText(hEditOriginal, content);
            free(content);
        }
        else
        {
            SetWindowText(hEditOriginal, "(Cannot read file)");
        }

        SetWindowText(hEditResult, "");
        SetWindowText(hStaticStatus, "Status: File loaded. Ready to encrypt.");
    }
}

/* ================== GET KEY ================== */
static int get_key(unsigned char *key, int *outKeySize)
{
    char hexKey[130] = {0};
    GetWindowText(hEditKey, hexKey, sizeof(hexKey));

    int hexLen = (int)strlen(hexKey);

    /* Determine key size from hex length */
    int keyBytes = 0;
    if (hexLen == 32)      keyBytes = 16;  /* AES-128 */
    else if (hexLen == 48) keyBytes = 24;  /* AES-192 */
    else if (hexLen == 64) keyBytes = 32;  /* AES-256 */
    else return -1;

    /* Validate hex */
    for (int i = 0; i < hexLen; i++)
    {
        char c = hexKey[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
            return -1;
    }

    hex_to_bytes(hexKey, key, keyBytes);
    *outKeySize = keyBytes;
    return 0;
}

/* ================== DO ENCRYPT ================== */
static void do_encrypt(HWND hwnd)
{
    if (g_inputPath[0] == '\0')
    {
        MessageBox(hwnd, "Please select an input file first!", "Error", MB_ICONWARNING);
        return;
    }

    unsigned char key[32];
    int keySize = 0;
    if (get_key(key, &keySize) != 0)
    {
        MessageBox(hwnd,
            "Invalid key!\n\n"
            "Please enter a valid hex key:\n"
            "  AES-128: 32 hex characters\n"
            "  AES-192: 48 hex characters\n"
            "  AES-256: 64 hex characters\n\n"
            "Or click one of the Random Key buttons.",
            "Error", MB_ICONWARNING);
        return;
    }

    /* Determine AES type name for display */
    const char *aesName = (keySize == 16) ? "AES-128" :
                          (keySize == 24) ? "AES-192" : "AES-256";

    SetWindowText(hStaticStatus, "Status: Encrypting...");
    UpdateWindow(hwnd);

    clock_t start = clock();
    int result = encrypt_file(g_inputPath, g_encPath, key, keySize);
    clock_t end = clock();

    if (result != 0)
    {
        MessageBox(hwnd, "Encryption failed! Cannot open file.", "Error", MB_ICONERROR);
        SetWindowText(hStaticStatus, "Status: Encryption FAILED");
        return;
    }

    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    char timeStr[128];
    sprintf(timeStr, "Encryption time:  %.6f s (%s)", elapsed, aesName);
    SetWindowText(hStaticTimeEnc, timeStr);

    /* Show encrypted content as hex */
    char *hexContent = read_file_hex(g_encPath);
    if (hexContent)
    {
        char *display = (char *)malloc(strlen(hexContent) + 256);
        sprintf(display, "[Encrypted Data - %s - HEX]\r\nOutput: %s\r\n\r\n%s",
                aesName, g_encPath, hexContent);
        SetWindowText(hEditResult, display);
        free(display);
        free(hexContent);
    }

    char statusMsg[256];
    sprintf(statusMsg, "Status: %s encryption completed! Output -> %s", aesName, g_encPath);
    SetWindowText(hStaticStatus, statusMsg);
}

/* ================== DO DECRYPT ================== */
static void do_decrypt(HWND hwnd)
{
    if (g_encPath[0] == '\0' || g_inputPath[0] == '\0')
    {
        MessageBox(hwnd, "Please select an input file and encrypt first!", "Error", MB_ICONWARNING);
        return;
    }

    unsigned char key[32];
    int keySize = 0;
    if (get_key(key, &keySize) != 0)
    {
        MessageBox(hwnd,
            "Invalid key!\n\n"
            "Please enter a valid hex key:\n"
            "  AES-128: 32 hex characters\n"
            "  AES-192: 48 hex characters\n"
            "  AES-256: 64 hex characters",
            "Error", MB_ICONWARNING);
        return;
    }

    /* Check if encrypted file exists */
    FILE *test = fopen(g_encPath, "rb");
    if (!test)
    {
        MessageBox(hwnd, "Encrypted file not found! Please encrypt first.", "Error", MB_ICONWARNING);
        return;
    }
    fclose(test);

    const char *aesName = (keySize == 16) ? "AES-128" :
                          (keySize == 24) ? "AES-192" : "AES-256";

    SetWindowText(hStaticStatus, "Status: Decrypting...");
    UpdateWindow(hwnd);

    clock_t start = clock();
    int result = decrypt_file(g_encPath, g_decPath, key, keySize);
    clock_t end = clock();

    if (result != 0)
    {
        MessageBox(hwnd, "Decryption failed!", "Error", MB_ICONERROR);
        SetWindowText(hStaticStatus, "Status: Decryption FAILED");
        return;
    }

    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    char timeStr[128];
    sprintf(timeStr, "Decryption time:  %.6f s (%s)", elapsed, aesName);
    SetWindowText(hStaticTimeDec, timeStr);

    /* Show decrypted content */
    long len = 0;
    char *content = read_file_text(g_decPath, &len);
    if (content)
    {
        char *display = (char *)malloc(strlen(content) + 256);
        sprintf(display, "[Decrypted Data - %s]\r\nOutput: %s\r\n\r\n%s",
                aesName, g_decPath, content);
        SetWindowText(hEditResult, display);
        free(display);
        free(content);
    }

    char statusMsg[256];
    sprintf(statusMsg, "Status: %s decryption completed! Output -> %s", aesName, g_decPath);
    SetWindowText(hStaticStatus, statusMsg);
}

/* ================== WINDOW PROCEDURE ================== */
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
        hBrBg = CreateSolidBrush(CLR_BG);
        hBrSurface = CreateSolidBrush(CLR_SURFACE);
        hBrInput = CreateSolidBrush(CLR_INPUT_BG);
        create_fonts();
        create_controls(hwnd);
        return 0;

    case WM_CTLCOLORSTATIC:
    {
        HDC hdc = (HDC)wParam;
        HWND hCtrl = (HWND)lParam;
        SetBkMode(hdc, TRANSPARENT);

        if (hCtrl == hTitle)
            SetTextColor(hdc, CLR_ACCENT);
        else if (hCtrl == hStaticKeyType)
            SetTextColor(hdc, CLR_PURPLE);
        else if (hCtrl == hStaticTimeEnc)
            SetTextColor(hdc, CLR_ACCENT3);
        else if (hCtrl == hStaticTimeDec)
            SetTextColor(hdc, CLR_ACCENT3);
        else if (hCtrl == hStaticStatus)
            SetTextColor(hdc, CLR_ACCENT2);
        else if (hCtrl == hLabelKey || hCtrl == hLabelFile ||
                 hCtrl == hLabelOriginal || hCtrl == hLabelResult)
            SetTextColor(hdc, CLR_ACCENT);
        else
            SetTextColor(hdc, CLR_TEXT);

        return (LRESULT)hBrBg;
    }

    case WM_CTLCOLOREDIT:
    {
        HDC hdc = (HDC)wParam;
        SetTextColor(hdc, CLR_TEXT);
        SetBkColor(hdc, CLR_INPUT_BG);
        return (LRESULT)hBrInput;
    }

    case WM_ERASEBKGND:
    {
        HDC hdc = (HDC)wParam;
        RECT rc;
        GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, hBrBg);

        /* Draw decorative line under title */
        HPEN hPen = CreatePen(PS_SOLID, 2, CLR_ACCENT);
        SelectObject(hdc, hPen);
        MoveToEx(hdc, 80, 54, NULL);
        LineTo(hdc, WIN_WIDTH - 80, 54);
        DeleteObject(hPen);

        return 1;
    }

    case WM_DRAWITEM:
    {
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
        draw_button(dis);
        return TRUE;
    }

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_BTN_BROWSE:
            do_browse(hwnd);
            break;
        case ID_BTN_ENCRYPT:
            do_encrypt(hwnd);
            break;
        case ID_BTN_DECRYPT:
            do_decrypt(hwnd);
            break;
        case ID_BTN_RANDOM_128:
        {
            char hexKey[65];
            g_keySize = 16;
            generate_random_key(hexKey, 16);
            SetWindowText(hEditKey, hexKey);
            update_key_type_label();
            SetWindowText(hStaticStatus, "Status: AES-128 key generated (32 hex chars)");
            break;
        }
        case ID_BTN_RANDOM_192:
        {
            char hexKey[65];
            g_keySize = 24;
            generate_random_key(hexKey, 24);
            SetWindowText(hEditKey, hexKey);
            update_key_type_label();
            SetWindowText(hStaticStatus, "Status: AES-192 key generated (48 hex chars)");
            break;
        }
        case ID_BTN_RANDOM_256:
        {
            char hexKey[65];
            g_keySize = 32;
            generate_random_key(hexKey, 32);
            SetWindowText(hEditKey, hexKey);
            update_key_type_label();
            SetWindowText(hStaticStatus, "Status: AES-256 key generated (64 hex chars)");
            break;
        }
        }
        return 0;

    case WM_DESTROY:
        DeleteObject(hBrBg);
        DeleteObject(hBrSurface);
        DeleteObject(hBrInput);
        DeleteObject(hFontTitle);
        DeleteObject(hFontLabel);
        DeleteObject(hFontNormal);
        DeleteObject(hFontMono);
        DeleteObject(hFontBtn);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd, msg, wParam, lParam);
}

/* ================== WINMAIN ================== */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow)
{
    (void)hPrev; (void)lpCmd;

    WNDCLASSEX wc = {0};
    wc.cbSize        = sizeof(WNDCLASSEX);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance      = hInst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm       = LoadIcon(NULL, IDI_APPLICATION);
    wc.lpszClassName  = "AES_GUI_CLASS";
    wc.hbrBackground  = NULL;

    if (!RegisterClassEx(&wc))
    {
        MessageBox(NULL, "Window class registration failed!", "Error", MB_ICONERROR);
        return 1;
    }

    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int winX = (screenW - WIN_WIDTH) / 2;
    int winY = (screenH - WIN_HEIGHT) / 2;

    HWND hwnd = CreateWindowEx(
        0, "AES_GUI_CLASS",
        "AES Encryption & Decryption (128 / 192 / 256)",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        winX, winY, WIN_WIDTH, WIN_HEIGHT,
        NULL, NULL, hInst, NULL);

    if (!hwnd)
    {
        MessageBox(NULL, "Window creation failed!", "Error", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
