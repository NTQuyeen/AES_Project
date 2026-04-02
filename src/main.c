#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "aes.h"

/* ======================== CONSTANTS ======================== */
#define WIN_WIDTH   820
#define WIN_HEIGHT  720
#define ID_COMBO_AES 1012

#define ID_BTN_BROWSE    1001
#define ID_BTN_ENCRYPT   1002
#define ID_BTN_DECRYPT   1003
#define ID_BTN_RANDOM    1004
#define ID_EDIT_KEY      1005
#define ID_EDIT_FILEPATH 1006
#define ID_EDIT_ORIGINAL 1007
#define ID_EDIT_RESULT   1008
#define ID_STATIC_TIME_ENC  1009
#define ID_STATIC_TIME_DEC  1010
#define ID_STATIC_STATUS    1011

/* ======================== COLORS ======================== */
#define CLR_BG          RGB(30, 30, 46)
#define CLR_SURFACE     RGB(45, 45, 65)
#define CLR_ACCENT      RGB(137, 180, 250)
#define CLR_ACCENT2     RGB(166, 227, 161)
#define CLR_ACCENT3     RGB(249, 226, 175)
#define CLR_RED         RGB(243, 139, 168)
#define CLR_TEXT        RGB(205, 214, 244)
#define CLR_SUBTEXT    RGB(147, 153, 178)
#define CLR_INPUT_BG   RGB(49, 50, 68)
#define CLR_BORDER     RGB(88, 91, 112)

/* ======================== GLOBALS ======================== */
static HWND hEditKey, hEditFilePath;
static HWND hEditOriginal, hEditResult;
static HWND hBtnBrowse, hBtnEncrypt, hBtnDecrypt, hBtnRandom;
static HWND hStaticTimeEnc, hStaticTimeDec, hStaticStatus;
static HWND hLabelKey, hLabelFile, hLabelOriginal, hLabelResult;
static HWND hTitle;
static HWND hComboAES;

static HBRUSH hBrBg, hBrSurface, hBrInput;
static HFONT hFontTitle, hFontLabel, hFontNormal, hFontMono, hFontBtn;


static char g_inputPath[MAX_PATH] = {0};
static char g_encPath[MAX_PATH]   = {0};
static char g_decPath[MAX_PATH]   = {0};

static int get_key_size(void);

/* ======================== HEX HELPERS ======================== */
static void hex_to_bytes(const char *hex, unsigned char *bytes, int keySize)
{
    for (int i = 0; i < keySize; i++)
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
    /* Extract directory */
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
    if (!fout)
    {
        fclose(fin);
        return -2;
    }

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
        AES_encrypt(buffer, encrypted, key, keySize);;
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
    if (!fout)
    {
        fclose(fin);
        return -2;
    }

    unsigned char buffer[16], decrypted[16], prev[16];
    int first = 1;

    while (fread(buffer, 1, 16, fin) == 16)
    {
        AES_decrypt(buffer, decrypted, key,keySize);
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

    /* Limit display to 4KB */
    long readLen = (len > 4096) ? 4096 : len;
    char *buf = (char *)malloc(readLen + 64);
    if (!buf)
    {
        fclose(f);
        return NULL;
    }

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
    if (!raw)
    {
        fclose(f);
        return NULL;
    }
    fread(raw, 1, readLen, f);
    fclose(f);

    /* Each byte -> "XX " (3 chars) + line breaks every 48 chars */
    char *hex = (char *)malloc(readLen * 4 + 256);
    if (!hex)
    {
        free(raw);
        return NULL;
    }

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
static void generate_random_key(char *hexOut)
{
    srand((unsigned)time(NULL) ^ (unsigned)GetTickCount());

    int keySize = get_key_size();   // 🔥 lấy loại AES (16 / 24 / 32)

    for (int i = 0; i < keySize; i++)
    {
        unsigned char b = (unsigned char)(rand() & 0xFF);
        sprintf(hexOut + i * 2, "%02X", b);
    }

    hexOut[keySize * 2] = '\0'; // 🔥 kết thúc chuỗi đúng độ dài
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

    if (id == ID_BTN_ENCRYPT)
    {
        bgColor = CLR_ACCENT;
        textColor = RGB(30,30,46);
    }
    else if (id == ID_BTN_DECRYPT)
    {
        bgColor = CLR_ACCENT2;
        textColor = RGB(30,30,46);
    }
    else if (id == ID_BTN_RANDOM)
    {
        bgColor = CLR_ACCENT3;
        textColor = RGB(30,30,46);
    }
    else
    {
        bgColor = CLR_SURFACE;
        textColor = CLR_TEXT;
    }

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

/* ================== DRAW SECTION PANEL ================== */
static void draw_section(HDC hdc, int x, int y, int w, int h, const char *label)
{
    HBRUSH hBr = CreateSolidBrush(CLR_SURFACE);
    HPEN hPen = CreatePen(PS_SOLID, 1, CLR_BORDER);
    SelectObject(hdc, hBr);
    SelectObject(hdc, hPen);
    RoundRect(hdc, x, y, x + w, y + h, 16, 16);

    if (label)
    {
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, CLR_ACCENT);
        SelectObject(hdc, hFontLabel);
        RECT r = { x + 14, y + 8, x + w - 14, y + 28 };
        DrawText(hdc, label, -1, &r, DT_LEFT | DT_SINGLELINE);
    }

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
                          "  AES-128  Encryption / Decryption",
                          WS_CHILD | WS_VISIBLE | SS_CENTER,
                          leftMargin, y, contentW, 36,
                          hwnd, NULL, NULL, NULL);
    SendMessage(hTitle, WM_SETFONT, (WPARAM)hFontTitle, TRUE);
    y += 50;

    /* Key label */
    hLabelKey = CreateWindow("STATIC", "AES Key (32 hex characters):",
                             WS_CHILD | WS_VISIBLE,
                             leftMargin, y, 250, 20,
                             hwnd, NULL, NULL, NULL);
    SendMessage(hLabelKey, WM_SETFONT, (WPARAM)hFontLabel, TRUE);
    y += 24;

    /* Key input */
    hEditKey = CreateWindowEx(WS_EX_CLIENTEDGE, "EDIT", "",
                              WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_UPPERCASE,
                              leftMargin, y, contentW - 120, 30,
                              hwnd, (HMENU)ID_EDIT_KEY, NULL, NULL);
    SendMessage(hEditKey, WM_SETFONT, (WPARAM)hFontMono, TRUE);
    SendMessage(hEditKey, EM_SETLIMITTEXT, 32, 0);

    /* Random button */
    hBtnRandom = CreateWindow("BUTTON", "Random Key",
                              WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                              leftMargin + contentW - 110, y, 110, 30,
                              hwnd, (HMENU)ID_BTN_RANDOM, NULL, NULL);
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
                                   leftMargin, y, contentW, 100,
                                   hwnd, (HMENU)ID_EDIT_ORIGINAL, NULL, NULL);
    SendMessage(hEditOriginal, WM_SETFONT, (WPARAM)hFontMono, TRUE);
    y += 110;

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
                                 leftMargin, y, contentW, 100,
                                 hwnd, (HMENU)ID_EDIT_RESULT, NULL, NULL);
    SendMessage(hEditResult, WM_SETFONT, (WPARAM)hFontMono, TRUE);
    y += 110;

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
    hStaticStatus = CreateWindow("STATIC", "Status: Ready",
                                 WS_CHILD | WS_VISIBLE,
                                 leftMargin, y, contentW, 22,
                                 hwnd, (HMENU)ID_STATIC_STATUS, NULL, NULL);
    SendMessage(hStaticStatus, WM_SETFONT, (WPARAM)hFontLabel, TRUE);

    hComboAES = CreateWindow("COMBOBOX", "",
                             WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
                             leftMargin, y, 200, 200,
                             hwnd, (HMENU)ID_COMBO_AES, NULL, NULL);

    SendMessage(hComboAES, CB_ADDSTRING, 0, (LPARAM)"AES-128");
    SendMessage(hComboAES, CB_ADDSTRING, 0, (LPARAM)"AES-192");
    SendMessage(hComboAES, CB_ADDSTRING, 0, (LPARAM)"AES-256");

    SendMessage(hComboAES, CB_SETCURSEL, 0, 0);
    y += 40;
}

static int get_key_size(void)
{
    int sel = SendMessage(hComboAES, CB_GETCURSEL, 0, 0);
    if (sel == 0) return 16;
    if (sel == 1) return 24;
    return 32;
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

        /* Show original content */
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
static int get_key(unsigned char *key, int keySize)
{
    char hexKey[128] = {0};
    GetWindowText(hEditKey, hexKey, sizeof(hexKey));

    int expectedLen = keySize * 2;

    if (strlen(hexKey) != expectedLen)
        return -1;

    hex_to_bytes(hexKey, key, keySize);
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

    int keySize = get_key_size();
    unsigned char key[32];

    if (get_key(key, keySize) != 0)
    {
        char err[100];
        sprintf(err, "Invalid key! Please enter exactly %d hex characters.", keySize * 2);
        MessageBox(hwnd, err, "Error", MB_ICONWARNING);
        return;
    }

    SetWindowText(hStaticStatus, "Status: Encrypting...");
    UpdateWindow(hwnd);

    /* ===== ĐO THỜI GIAN CHUẨN ===== */
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    int result = encrypt_file(g_inputPath, g_encPath, key, keySize);

    QueryPerformanceCounter(&end);
    /* ============================== */

    if (result != 0)
    {
        MessageBox(hwnd, "Encryption failed! Cannot open file.", "Error", MB_ICONERROR);
        SetWindowText(hStaticStatus, "Status: Encryption FAILED");
        return;
    }

    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;

    char timeStr[128];
    sprintf(timeStr, "Encryption time: %.6f s (%.3f ms)", elapsed, elapsed * 1000);
    SetWindowText(hStaticTimeEnc, timeStr);

    /* Show encrypted content as hex */
    char *hexContent = read_file_hex(g_encPath);
    if (hexContent)
    {
        char *display = (char *)malloc(strlen(hexContent) + 128);
        sprintf(display, "[Encrypted Data - HEX]\r\nOutput: %s\r\n\r\n%s", g_encPath, hexContent);
        SetWindowText(hEditResult, display);
        free(display);
        free(hexContent);
    }

    char statusMsg[256];
    sprintf(statusMsg, "Status: Encryption completed! Output -> %s", g_encPath);
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

    int keySize = get_key_size();
    unsigned char key[32];

    if (get_key(key, keySize) != 0)
    {
        char err[100];
        sprintf(err, "Invalid key! Please enter exactly %d hex characters.", keySize * 2);
        MessageBox(hwnd, err, "Error", MB_ICONWARNING);
        return;
    }

    FILE *test = fopen(g_encPath, "rb");
    if (!test)
    {
        MessageBox(hwnd, "Encrypted file not found! Please encrypt first.", "Error", MB_ICONWARNING);
        return;
    }
    fclose(test);

    SetWindowText(hStaticStatus, "Status: Decrypting...");
    UpdateWindow(hwnd);

    /* ===== ĐO THỜI GIAN CHUẨN ===== */
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    int result = decrypt_file(g_encPath, g_decPath, key, keySize);

    QueryPerformanceCounter(&end);
    /* ============================== */

    if (result != 0)
    {
        MessageBox(hwnd, "Decryption failed!", "Error", MB_ICONERROR);
        SetWindowText(hStaticStatus, "Status: Decryption FAILED");
        return;
    }

    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;

    char timeStr[128];
    sprintf(timeStr, "Decryption time: %.6f s (%.3f ms)", elapsed, elapsed * 1000);
    SetWindowText(hStaticTimeDec, timeStr);

    /* Show decrypted content */
    long len = 0;
    char *content = read_file_text(g_decPath, &len);
    if (content)
    {
        char *display = (char *)malloc(strlen(content) + 128);
        sprintf(display, "[Decrypted Data]\r\nOutput: %s\r\n\r\n%s", g_decPath, content);
        SetWindowText(hEditResult, display);
        free(display);
        free(content);
    }

    char statusMsg[256];
    sprintf(statusMsg, "Status: Decryption completed! Output -> %s", g_decPath);
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
        case ID_BTN_RANDOM:
        {
            char hexKey[33];
            generate_random_key(hexKey);
            SetWindowText(hEditKey, hexKey);
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
    (void)hPrev;
    (void)lpCmd;

    WNDCLASSEX wc = {0};
    wc.cbSize        = sizeof(WNDCLASSEX);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance      = hInst;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm       = LoadIcon(NULL, IDI_APPLICATION);
    wc.lpszClassName  = "AES_GUI_CLASS";
    wc.hbrBackground  = NULL;  /* We paint background ourselves */

    if (!RegisterClassEx(&wc))
    {
        MessageBox(NULL, "Window class registration failed!", "Error", MB_ICONERROR);
        return 1;
    }

    /* Center window on screen */
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int winX = (screenW - WIN_WIDTH) / 2;
    int winY = (screenH - WIN_HEIGHT) / 2;

    HWND hwnd = CreateWindowEx(
                    0, "AES_GUI_CLASS",
                    "AES-128 Encryption & Decryption",
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
