#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <random>
#include <string>
#include <vector>

// ============================================================================
//  MinGW 8.1 缺失的声明补丁
// ============================================================================
#ifndef WM_DPICHANGED
#define WM_DPICHANGED 0x02E0
#endif

#ifndef WM_DPICHANGED_BEFOREPARENT
#define WM_DPICHANGED_BEFOREPARENT 0x02E2
#endif
#ifndef WM_DPICHANGED_AFTERPARENT
#define WM_DPICHANGED_AFTERPARENT 0x02E3
#endif

// DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 就是 (HANDLE)-4
#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 ((HANDLE)-4)
#endif

// ============================================================================
//  SHA-256
// ============================================================================
class SHA256 {
    uint32_t h[8];
    uint8_t  buffer[64];
    uint64_t totalLen;
    size_t   bufLen;

    static constexpr uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    void transform(const uint8_t* block) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(block[i*4]) << 24) | (uint32_t(block[i*4+1]) << 16)
                 | (uint32_t(block[i*4+2]) << 8) | uint32_t(block[i*4+3]);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
public:
    SHA256() { reset(); }
    void reset() {
        h[0]=0x6a09e667; h[1]=0xbb67ae85; h[2]=0x3c6ef372; h[3]=0xa54ff53a;
        h[4]=0x510e527f; h[5]=0x9b05688c; h[6]=0x1f83d9ab; h[7]=0x5be0cd19;
        totalLen = 0; bufLen = 0;
    }
    void update(const uint8_t* data, size_t len) {
        totalLen += len;
        while (len > 0) {
            size_t n = std::min(len, size_t(64 - bufLen));
            std::memcpy(buffer + bufLen, data, n);
            bufLen += n; data += n; len -= n;
            if (bufLen == 64) { transform(buffer); bufLen = 0; }
        }
    }
    std::array<uint8_t, 32> final() {
        uint64_t bitLen = totalLen * 8;
        size_t A = bufLen + 1;
        size_t k = (64 - ((A + 8) % 64)) % 64;
        uint8_t pad[128] = {};
        pad[0] = 0x80;
        for (int i = 0; i < 8; ++i) pad[1 + k + i] = uint8_t(bitLen >> (56 - i*8));
        update(pad, 1 + k + 8);
        std::array<uint8_t, 32> out;
        for (int i = 0; i < 8; ++i) {
            out[i*4]   = uint8_t(h[i] >> 24);
            out[i*4+1] = uint8_t(h[i] >> 16);
            out[i*4+2] = uint8_t(h[i] >> 8);
            out[i*4+3] = uint8_t(h[i]);
        }
        return out;
    }
    static std::array<uint8_t, 32> hash(const uint8_t* data, size_t len) {
        SHA256 s; s.update(data, len); return s.final();
    }
};

class HMAC_SHA256 {
    SHA256 inner;
    std::array<uint8_t, 64> oKeyPad;
public:
    HMAC_SHA256(const uint8_t* key, size_t keyLen) {
        std::array<uint8_t, 64> keyPad{};
        if (keyLen > 64) {
            auto h = SHA256::hash(key, keyLen);
            std::memcpy(keyPad.data(), h.data(), 32);
        } else std::memcpy(keyPad.data(), key, keyLen);
        std::array<uint8_t, 64> iKeyPad{};
        for (int i = 0; i < 64; ++i) {
            iKeyPad[i] = keyPad[i] ^ 0x36;
            oKeyPad[i] = keyPad[i] ^ 0x5c;
        }
        inner.update(iKeyPad.data(), 64);
    }
    void update(const uint8_t* data, size_t len) { inner.update(data, len); }
    std::array<uint8_t, 32> final() {
        auto ih = inner.final();
        SHA256 outer;
        outer.update(oKeyPad.data(), 64);
        outer.update(ih.data(), 32);
        return outer.final();
    }
};

std::vector<uint8_t> pbkdf2(const std::string& password,
                            const uint8_t* salt, size_t saltLen,
                            int iterations, size_t dkLen) {
    std::vector<uint8_t> dk(dkLen);
    size_t blocks = (dkLen + 31) / 32;
    for (size_t i = 1; i <= blocks; ++i) {
        uint8_t counter[4] = { uint8_t(i>>24), uint8_t(i>>16), uint8_t(i>>8), uint8_t(i) };
        HMAC_SHA256 hmac(reinterpret_cast<const uint8_t*>(password.data()), password.size());
        hmac.update(salt, saltLen);
        hmac.update(counter, 4);
        auto u = hmac.final();
        auto t = u;
        for (int j = 1; j < iterations; ++j) {
            HMAC_SHA256 h2(u.data(), 32);
            u = h2.final();
            for (int k = 0; k < 32; ++k) t[k] ^= u[k];
        }
        size_t copyLen = std::min<size_t>(32, dkLen - (i - 1) * 32);
        std::memcpy(dk.data() + (i - 1) * 32, t.data(), copyLen);
    }
    return dk;
}

class ChaCha20 {
    uint32_t state[16];
    uint8_t  keystream[64];
    size_t   pos;
    static uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
    static void QR(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl(d, 16);
        c += d; b ^= c; b = rotl(b, 12);
        a += b; d ^= a; d = rotl(d, 8);
        c += d; b ^= c; b = rotl(b, 7);
    }
    void generateBlock() {
        uint32_t x[16];
        std::memcpy(x, state, sizeof(x));
        for (int i = 0; i < 10; ++i) {
            QR(x[0],x[4],x[8],x[12]); QR(x[1],x[5],x[9],x[13]);
            QR(x[2],x[6],x[10],x[14]); QR(x[3],x[7],x[11],x[15]);
            QR(x[0],x[5],x[10],x[15]); QR(x[1],x[6],x[11],x[12]);
            QR(x[2],x[7],x[8],x[13]); QR(x[3],x[4],x[9],x[14]);
        }
        for (int i = 0; i < 16; ++i) x[i] += state[i];
        for (int i = 0; i < 16; ++i) {
            keystream[i*4]   = uint8_t(x[i]);
            keystream[i*4+1] = uint8_t(x[i] >> 8);
            keystream[i*4+2] = uint8_t(x[i] >> 16);
            keystream[i*4+3] = uint8_t(x[i] >> 24);
        }
        state[12]++;
    }
public:
    ChaCha20(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter = 0) {
        state[0]=0x61707865; state[1]=0x3320646e; state[2]=0x79622d32; state[3]=0x6b206574;
        for (int i = 0; i < 8; ++i)
            state[4+i] = uint32_t(key[i*4]) | (uint32_t(key[i*4+1]) << 8)
                       | (uint32_t(key[i*4+2]) << 16) | (uint32_t(key[i*4+3]) << 24);
        state[12] = counter;
        for (int i = 0; i < 3; ++i)
            state[13+i] = uint32_t(nonce[i*4]) | (uint32_t(nonce[i*4+1]) << 8)
                        | (uint32_t(nonce[i*4+2]) << 16) | (uint32_t(nonce[i*4+3]) << 24);
        pos = 64;
    }
    void process(uint8_t* data, size_t len) {
        while (len > 0) {
            if (pos == 64) { generateBlock(); pos = 0; }
            size_t n = std::min(len, size_t(64 - pos));
            for (size_t i = 0; i < n; ++i) data[i] ^= keystream[pos + i];
            data += n; pos += n; len -= n;
        }
    }
};

void randomBytes(uint8_t* buf, size_t len) {
    std::random_device rd;
    std::seed_seq seq{ rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd(),
        static_cast<unsigned>(std::chrono::high_resolution_clock::now()
            .time_since_epoch().count()) };
    std::mt19937_64 gen(seq);
    for (size_t i = 0; i < len; ++i) buf[i] = static_cast<uint8_t>(gen() & 0xff);
}

std::string wideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], len, nullptr, nullptr);
    return s;
}

// ============================================================================
//  文件格式
// ============================================================================
// 加密后文件布局：
//   [原始文件数据 originalSize 字节]
//   [record 0][record 1]...[record N-1]   N * 48 字节
//   [fixed 36 字节]  ← 放在最末尾
// ============================================================================
constexpr uint32_t DEFAULT_BLOCK_SIZE = 1024u * 1024u;
constexpr size_t   SALT_LEN    = 16;
constexpr size_t   NONCE_LEN   = 12;
constexpr size_t   TAG_LEN     = 32;
constexpr size_t   KEY_LEN     = 32;
constexpr int      PBKDF2_ITER = 100000;
constexpr size_t   FOOTER_FIXED = 8 + 4 + 4 + 4 + SALT_LEN;   // 36
constexpr size_t   RECORD_SIZE  = 4 + NONCE_LEN + TAG_LEN;    // 48
const uint8_t MAGIC[8] = {'P','H','E','N','C','0','4','\0'};  // 版本号改为 04

bool readAt(HANDLE h, uint64_t offset, void* buf, size_t len) {
    if (len == 0) return true;
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) return false;
    uint8_t* p = (uint8_t*)buf;
    size_t remaining = len;
    while (remaining > 0) {
        DWORD chunk = (remaining > 0x40000000u) ? 0x40000000u : (DWORD)remaining;
        DWORD got = 0;
        if (!ReadFile(h, p, chunk, &got, NULL) || got == 0) return false;
        p += got; remaining -= got;
    }
    return true;
}

bool writeAt(HANDLE h, uint64_t offset, const void* buf, size_t len) {
    if (len == 0) return true;
    LARGE_INTEGER li; li.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(h, li, NULL, FILE_BEGIN)) return false;
    const uint8_t* p = (const uint8_t*)buf;
    size_t remaining = len;
    while (remaining > 0) {
        DWORD chunk = (remaining > 0x40000000u) ? 0x40000000u : (DWORD)remaining;
        DWORD wrote = 0;
        if (!WriteFile(h, p, chunk, &wrote, NULL) || wrote == 0) return false;
        p += wrote; remaining -= wrote;
    }
    return true;
}

bool encryptFileW(const std::wstring& path, const std::string& password,
                  double ratio, std::wstring& err) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { err = L"无法打开文件"; return false; }

    LARGE_INTEGER li;
    if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0) {
        CloseHandle(h); err = L"文件为空"; return false;
    }
    uint64_t originalSize = (uint64_t)li.QuadPart;
    uint32_t blockSize = DEFAULT_BLOCK_SIZE;
    uint32_t totalBlocks = (uint32_t)((originalSize + blockSize - 1) / blockSize);
    if (totalBlocks == 0) totalBlocks = 1;

    double r = ratio;
    if (r <= 0.0) r = 0.01;
    if (r > 1.0) r = 1.0;
    uint32_t encCount = (uint32_t)std::floor((double)totalBlocks * r + 0.5);
    if (encCount < 1) encCount = 1;
    if (encCount > totalBlocks) encCount = totalBlocks;

    std::vector<uint32_t> indices(totalBlocks);
    for (uint32_t i = 0; i < totalBlocks; ++i) indices[i] = i;
    {
        std::random_device rd;
        std::seed_seq seq{rd(), rd(), rd(), rd(), rd(), rd(), rd(), rd()};
        std::mt19937_64 gen(seq);
        std::shuffle(indices.begin(), indices.end(), gen);
    }
    indices.resize(encCount);
    std::sort(indices.begin(), indices.end());

    uint8_t salt[SALT_LEN];
    randomBytes(salt, SALT_LEN);

    auto km = pbkdf2(password, salt, SALT_LEN, PBKDF2_ITER, KEY_LEN * 2);
    const uint8_t* encKey = km.data();
    const uint8_t* macKey = km.data() + KEY_LEN;

    std::vector<uint8_t> blockBuf(blockSize);
    struct Rec { uint32_t idx; uint8_t nonce[NONCE_LEN]; uint8_t tag[TAG_LEN]; };
    std::vector<Rec> records;
    records.reserve(encCount);

    for (uint32_t bi : indices) {
        uint64_t offset = (uint64_t)bi * blockSize;
        uint32_t actualSize = blockSize;
        if (offset + blockSize > originalSize) actualSize = (uint32_t)(originalSize - offset);
        if (actualSize == 0) continue;
        if (!readAt(h, offset, blockBuf.data(), actualSize)) {
            CloseHandle(h); err = L"读取块失败"; return false;
        }
        Rec rec; rec.idx = bi;
        randomBytes(rec.nonce, NONCE_LEN);
        ChaCha20 chacha(encKey, rec.nonce, 0);
        chacha.process(blockBuf.data(), actualSize);

        HMAC_SHA256 hmac(macKey, KEY_LEN);
        uint8_t idxBuf[4] = { uint8_t(bi), uint8_t(bi>>8), uint8_t(bi>>16), uint8_t(bi>>24) };
        hmac.update(idxBuf, 4);
        hmac.update(salt, SALT_LEN);
        hmac.update(rec.nonce, NONCE_LEN);
        hmac.update(blockBuf.data(), actualSize);
        auto t = hmac.final();
        std::memcpy(rec.tag, t.data(), TAG_LEN);

        if (!writeAt(h, offset, blockBuf.data(), actualSize)) {
            CloseHandle(h); err = L"写回块失败"; return false;
        }
        records.push_back(rec);
    }

    // ============ 关键修复：records 在前，fixed 在后 ============
    std::vector<uint8_t> footer;
    footer.reserve(FOOTER_FIXED + records.size() * RECORD_SIZE);

    auto pushU32 = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) footer.push_back(uint8_t(v >> (8 * i)));
    };

    // 1) 先写 records
    for (auto& rr : records) {
        pushU32(rr.idx);
        footer.insert(footer.end(), rr.nonce, rr.nonce + NONCE_LEN);
        footer.insert(footer.end(), rr.tag, rr.tag + TAG_LEN);
    }
    // 2) 再写 fixed
    footer.insert(footer.end(), MAGIC, MAGIC + 8);
    pushU32(blockSize);
    pushU32(totalBlocks);
    pushU32((uint32_t)records.size());
    footer.insert(footer.end(), salt, salt + SALT_LEN);

    if (!writeAt(h, originalSize, footer.data(), footer.size())) {
        CloseHandle(h); err = L"写入尾部失败"; return false;
    }
    CloseHandle(h);
    return true;
}

bool decryptFileW(const std::wstring& path, const std::string& password,
                  std::wstring& err) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { err = L"无法打开文件"; return false; }

    LARGE_INTEGER li;
    if (!GetFileSizeEx(h, &li) || (uint64_t)li.QuadPart < FOOTER_FIXED) {
        CloseHandle(h); err = L"文件过小"; return false;
    }
    uint64_t fileSize = (uint64_t)li.QuadPart;

    // 从末尾读 36 字节 fixed
    uint8_t fixed[FOOTER_FIXED];
    if (!readAt(h, fileSize - FOOTER_FIXED, fixed, FOOTER_FIXED)) {
        CloseHandle(h); err = L"读取尾部失败"; return false;
    }
    if (std::memcmp(fixed, MAGIC, 8) != 0) {
        CloseHandle(h); err = L"不是本程序加密的文件"; return false;
    }
    auto readU32 = [](const uint8_t* p) -> uint32_t {
        return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
             | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    };
    uint32_t blockSize   = readU32(fixed + 8);
    uint32_t totalBlocks = readU32(fixed + 12);
    uint32_t encCount    = readU32(fixed + 16);
    const uint8_t* salt  = fixed + 20;

    if (blockSize == 0 || encCount == 0 || encCount > totalBlocks ||
        blockSize > 256u * 1024u * 1024u) {
        CloseHandle(h); err = L"尾部信息无效"; return false;
    }
    uint64_t recordsSize = (uint64_t)encCount * RECORD_SIZE;
    if (fileSize < FOOTER_FIXED + recordsSize) {
        CloseHandle(h); err = L"文件结构异常"; return false;
    }
    // records 位于 [originalSize, originalSize + recordsSize)
    uint64_t originalSize = fileSize - FOOTER_FIXED - recordsSize;

    std::vector<uint8_t> recBuf((size_t)recordsSize);
    if (!readAt(h, originalSize, recBuf.data(), recBuf.size())) {
        CloseHandle(h); err = L"读取记录失败"; return false;
    }
    auto km = pbkdf2(password, salt, SALT_LEN, PBKDF2_ITER, KEY_LEN * 2);
    const uint8_t* encKey = km.data();
    const uint8_t* macKey = km.data() + KEY_LEN;

    std::vector<uint8_t> blockBuf(blockSize);
    for (uint32_t i = 0; i < encCount; ++i) {
        const uint8_t* rec = recBuf.data() + (size_t)i * RECORD_SIZE;
        uint32_t bi = readU32(rec);
        const uint8_t* nonce = rec + 4;
        const uint8_t* tag   = rec + 16;
        if (bi >= totalBlocks) {
            CloseHandle(h); err = L"块索引无效"; return false;
        }
        uint64_t offset = (uint64_t)bi * blockSize;
        uint32_t actualSize = blockSize;
        if (offset + blockSize > originalSize) actualSize = (uint32_t)(originalSize - offset);
        if (actualSize == 0) {
            CloseHandle(h); err = L"块大小为零"; return false;
        }
        if (!readAt(h, offset, blockBuf.data(), actualSize)) {
            CloseHandle(h); err = L"读取块失败"; return false;
        }
        HMAC_SHA256 hmac(macKey, KEY_LEN);
        uint8_t idxBuf[4] = { uint8_t(bi), uint8_t(bi>>8), uint8_t(bi>>16), uint8_t(bi>>24) };
        hmac.update(idxBuf, 4);
        hmac.update(salt, SALT_LEN);
        hmac.update(nonce, NONCE_LEN);
        hmac.update(blockBuf.data(), actualSize);
        auto myTag = hmac.final();
        uint8_t diff = 0;
        for (size_t j = 0; j < TAG_LEN; ++j) diff |= (myTag[j] ^ tag[j]);
        if (diff != 0) {
            CloseHandle(h); err = L"认证失败（密码错误或文件损坏）"; return false;
        }
        ChaCha20 chacha(encKey, nonce, 0);
        chacha.process(blockBuf.data(), actualSize);
        if (!writeAt(h, offset, blockBuf.data(), actualSize)) {
            CloseHandle(h); err = L"写回明文失败"; return false;
        }
    }
    LARGE_INTEGER newSize; newSize.QuadPart = (LONGLONG)originalSize;
    if (!SetFilePointerEx(h, newSize, NULL, FILE_BEGIN) || !SetEndOfFile(h)) {
        CloseHandle(h); err = L"截断文件失败"; return false;
    }
    CloseHandle(h);
    return true;
}

// ============================================================================
//  ==================== GUI（DPI 感知版） ====================
// ============================================================================

int g_dpi = 96;
int S(int v) { return MulDiv(v, g_dpi, 96); }

HWND g_hwnd = NULL;
HWND g_lbPw = NULL, g_lbRatio = NULL, g_lbPct = NULL;
HWND g_pwEdit = NULL, g_showPw = NULL, g_ratioEdit = NULL;
HWND g_btnAdd = NULL, g_btnRemove = NULL, g_btnClear = NULL;
HWND g_btnEnc = NULL, g_btnDec = NULL;
HWND g_list = NULL, g_log = NULL;

HFONT g_font = NULL, g_fontBold = NULL;
HBRUSH g_brushBg = NULL;

enum BtnStyle { BTN_NORMAL = 0, BTN_PRIMARY = 1 };
struct BtnData { HWND hwnd; std::wstring text; int style; bool hover; };
BtnData g_btns[8];
int g_btnCount = 0;
WNDPROC g_oldBtnProc = NULL;
WNDPROC g_oldListProc = NULL;

BtnData* FindBtn(HWND h) {
    for (int i = 0; i < g_btnCount; ++i)
        if (g_btns[i].hwnd == h) return &g_btns[i];
    return nullptr;
}

void PaintButton(const DRAWITEMSTRUCT* dis, BtnData* b) {
    HDC hdc = dis->hDC;
    RECT rc = dis->rcItem;
    bool pressed  = (dis->itemState & ODS_SELECTED) != 0;
    bool disabled = (dis->itemState & ODS_DISABLED) != 0;
    bool hot      = b ? b->hover : false;

    COLORREF bg, border, fg;
    if (b && b->style == BTN_PRIMARY) {
        if (disabled)      { bg = RGB(198,198,198); border = bg; fg = RGB(245,245,245); }
        else if (pressed)  { bg = RGB(0, 80, 150);  border = bg; fg = RGB(255,255,255); }
        else if (hot)      { bg = RGB(25, 117, 197); border = bg; fg = RGB(255,255,255); }
        else               { bg = RGB(0, 103, 192);  border = bg; fg = RGB(255,255,255); }
    } else {
        if (disabled)      { bg = RGB(250,250,250); border = RGB(230,230,230); fg = RGB(170,170,170); }
        else if (pressed)  { bg = RGB(237,237,237); border = RGB(200,200,200); fg = RGB(26,26,26); }
        else if (hot)      { bg = RGB(245,245,245); border = RGB(208,208,208); fg = RGB(26,26,26); }
        else               { bg = RGB(253,253,253); border = RGB(218,218,218); fg = RGB(26,26,26); }
    }

    int radius = S(9);
    HRGN rgn = CreateRoundRectRgn(rc.left, rc.top, rc.right + 1, rc.bottom + 1,
                                  radius, radius);
    HBRUSH br = CreateSolidBrush(bg);
    FillRgn(hdc, rgn, br);
    DeleteObject(br);
    DeleteObject(rgn);

    HPEN pen = CreatePen(PS_SOLID, 1, border);
    HPEN oldPen = (HPEN)SelectObject(hdc, pen);
    HBRUSH oldBrush = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
    RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, radius, radius);
    SelectObject(hdc, oldBrush);
    SelectObject(hdc, oldPen);
    DeleteObject(pen);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, fg);
    RECT tr = rc;
    HFONT old = (HFONT)SelectObject(hdc, g_font);
    DrawTextW(hdc, b ? b->text.c_str() : L"", -1, &tr,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, old);
}

LRESULT CALLBACK BtnProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    BtnData* b = FindBtn(hwnd);
    if (b) {
        if (msg == WM_MOUSEMOVE && !b->hover) {
            b->hover = true;
            InvalidateRect(hwnd, NULL, FALSE);
            TRACKMOUSEEVENT tme = {sizeof(tme), TME_LEAVE, hwnd, 0};
            TrackMouseEvent(&tme);
        } else if (msg == WM_MOUSELEAVE) {
            if (b->hover) { b->hover = false; InvalidateRect(hwnd, NULL, FALSE); }
        }
    }
    return CallWindowProc(g_oldBtnProc, hwnd, msg, wParam, lParam);
}

HWND MakeButton(HWND parent, int id, const wchar_t* text, int style,
                int x, int y, int w, int h) {
    HWND hBtn = CreateWindowExW(0, L"BUTTON", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
        x, y, w, h, parent, (HMENU)(INT_PTR)id, NULL, NULL);
    BtnData& info = g_btns[g_btnCount++];
    info.hwnd = hBtn;
    info.text = text;
    info.style = style;
    info.hover = false;
    if (!g_oldBtnProc)
        g_oldBtnProc = (WNDPROC)SetWindowLongPtrW(hBtn, GWLP_WNDPROC,
                                                  (LONG_PTR)BtnProc);
    else
        SetWindowLongPtrW(hBtn, GWLP_WNDPROC, (LONG_PTR)BtnProc);
    return hBtn;
}

const int L_WIN_W = 500;
const int L_WIN_H = 420;
const int L_M = 14;
const int L_ROW_H = 26;
const int L_BTN_H = 34;

const int L_ROW1_Y = 14;
const int L_ROW2_Y = 48;
const int L_BTN_Y  = 84;
const int L_LIST_Y = 128;
const int L_LIST_H = 140;
const int L_LOG_Y  = 280;
const int L_LOG_H  = L_WIN_H - L_LOG_Y - L_M;

#define ID_PW      2001
#define ID_SHOWPW  2002
#define ID_RATIO   2003
#define ID_ADD     2004
#define ID_CLEAR   2005
#define ID_ENC     2006
#define ID_DEC     2007
#define ID_LIST    2008
#define ID_LOG     2009
#define ID_REMOVE  2010

void LogLine(const std::wstring& msg) {
    int len = GetWindowTextLengthW(g_log);
    SendMessageW(g_log, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    std::wstring line = msg + L"\r\n";
    SendMessageW(g_log, EM_REPLACESEL, 0, (LPARAM)line.c_str());
    SendMessageW(g_log, EM_SCROLLCARET, 0, 0);
}

void AddFile(const std::wstring& path) {
    int count = (int)SendMessageW(g_list, LB_GETCOUNT, 0, 0);
    for (int i = 0; i < count; ++i) {
        int len = (int)SendMessageW(g_list, LB_GETTEXTLEN, i, 0);
        if (len <= 0) continue;
        std::wstring s(len, L'\0');
        SendMessageW(g_list, LB_GETTEXT, i, (LPARAM)&s[0]);
        if (s == path) return;
    }
    SendMessageW(g_list, LB_ADDSTRING, 0, (LPARAM)path.c_str());
}

void OnRemoveSelected(HWND hWnd) {
    int count = (int)SendMessageW(g_list, LB_GETCOUNT, 0, 0);
    bool any = false;
    for (int i = count - 1; i >= 0; --i) {
        if (SendMessageW(g_list, LB_GETSEL, i, 0) > 0) {
            SendMessageW(g_list, LB_DELETESTRING, i, 0);
            any = true;
        }
    }
    if (!any)
        MessageBoxW(hWnd, L"请先在列表中选择要移除的文件",
                    L"提示", MB_OK | MB_ICONINFORMATION);
}

LRESULT CALLBACK ListProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_KEYDOWN && wParam == VK_DELETE) {
        OnRemoveSelected(GetParent(hwnd));
        return 0;
    }
    return CallWindowProc(g_oldListProc, hwnd, msg, wParam, lParam);
}

void OnAddFiles(HWND hWnd) {
    static wchar_t buf[65536];
    std::memset(buf, 0, sizeof(buf));
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = L"所有文件\0*.*\0\0";
    ofn.lpstrFile = buf;
    ofn.nMaxFile = 65536;
    ofn.Flags = OFN_ALLOWMULTISELECT | OFN_EXPLORER
              | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    if (!GetOpenFileNameW(&ofn)) return;

    std::wstring dir = buf;
    wchar_t* p = buf + dir.size() + 1;
    if (*p == 0) {
        AddFile(dir);
    } else {
        while (*p) {
            std::wstring name = p;
            AddFile(dir + L"\\" + name);
            p += name.size() + 1;
        }
    }
}

void OnProcess(HWND hWnd, bool doEncrypt) {
    int pwLen = GetWindowTextLengthW(g_pwEdit);
    if (pwLen <= 0) {
        MessageBoxW(hWnd, L"请先输入密码", L"提示", MB_OK | MB_ICONINFORMATION);
        return;
    }
    std::wstring pwW(pwLen, L'\0');
    GetWindowTextW(g_pwEdit, &pwW[0], pwLen + 1);

    int count = (int)SendMessageW(g_list, LB_GETCOUNT, 0, 0);
    if (count <= 0) {
        MessageBoxW(hWnd, L"请先添加要处理的文件", L"提示", MB_OK | MB_ICONINFORMATION);
        return;
    }

    wchar_t rb[16] = {};
    GetWindowTextW(g_ratioEdit, rb, 16);
    int rv = _wtoi(rb);
    if (rv < 1) rv = 1;
    if (rv > 100) rv = 100;
    double ratio = rv / 100.0;

    std::vector<std::wstring> paths;
    paths.reserve(count);
    for (int i = 0; i < count; ++i) {
        int len = (int)SendMessageW(g_list, LB_GETTEXTLEN, i, 0);
        std::wstring s(len, L'\0');
        SendMessageW(g_list, LB_GETTEXT, i, (LPARAM)&s[0]);
        paths.push_back(s);
    }
    std::string pwUtf8 = wideToUtf8(pwW);

    EnableWindow(g_btnAdd, FALSE);
    EnableWindow(g_btnRemove, FALSE);
    EnableWindow(g_btnClear, FALSE);
    EnableWindow(g_btnEnc, FALSE);
    EnableWindow(g_btnDec, FALSE);
    HCURSOR oldCur = SetCursor(LoadCursor(NULL, IDC_WAIT));

    if (doEncrypt) {
        wchar_t b[64];
        swprintf(b, 64, L"===== 开始加密（比例 %d%%）=====", rv);
        LogLine(b);
    } else {
        LogLine(L"===== 开始解密 =====");
    }
    UpdateWindow(g_log);

    int ok = 0;
    for (auto& p : paths) {
        std::wstring err;
        bool r = doEncrypt ? encryptFileW(p, pwUtf8, ratio, err)
                           : decryptFileW(p, pwUtf8, err);
        size_t sl = p.find_last_of(L"\\/");
        std::wstring name = (sl == std::wstring::npos) ? p : p.substr(sl + 1);
        if (r) { ++ok; LogLine(L"[OK]   " + name); }
        else    { LogLine(L"[失败] " + name + L"  → " + err); }
        UpdateWindow(g_log);
    }
    LogLine(L"完成: " + std::to_wstring(ok) + L" / " +
            std::to_wstring(paths.size()) + L" 个文件");

    SetCursor(oldCur);
    EnableWindow(g_btnAdd, TRUE);
    EnableWindow(g_btnRemove, TRUE);
    EnableWindow(g_btnClear, TRUE);
    EnableWindow(g_btnEnc, TRUE);
    EnableWindow(g_btnDec, TRUE);
}

void CreateFonts() {
    if (g_font)     DeleteObject(g_font);
    if (g_fontBold) DeleteObject(g_fontBold);
    g_font = CreateFontW(-S(15), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    g_fontBold = CreateFontW(-S(15), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
}

BOOL CALLBACK SetFontProc(HWND h, LPARAM lp) {
    SendMessageW(h, WM_SETFONT, (WPARAM)lp, TRUE);
    return TRUE;
}

void LayoutAll(HWND hWnd) {
    MoveWindow(g_lbPw,      S(L_M),                  S(L_ROW1_Y + 3),
                            S(36),                   S(L_ROW_H), TRUE);
    MoveWindow(g_pwEdit,    S(L_M + 40),             S(L_ROW1_Y),
                            S(200),                  S(L_ROW_H), TRUE);
    MoveWindow(g_showPw,    S(L_M + 250),            S(L_ROW1_Y + 2),
                            S(100),                  S(22), TRUE);

    MoveWindow(g_lbRatio,   S(L_M),                  S(L_ROW2_Y + 3),
                            S(64),                   S(L_ROW_H), TRUE);
    MoveWindow(g_ratioEdit, S(L_M + 68),             S(L_ROW2_Y),
                            S(50),                   S(L_ROW_H), TRUE);
    MoveWindow(g_lbPct,     S(L_M + 122),            S(L_ROW2_Y + 3),
                            S(20),                   S(L_ROW_H), TRUE);

    int winW = S(L_WIN_W);
    int m = S(L_M);
    int bw = S(68);
    int bh = S(L_BTN_H);
    int by = S(L_BTN_Y);
    MoveWindow(g_btnAdd,    m,                         by, S(90), S(L_BTN_H), TRUE);
    MoveWindow(g_btnRemove, m + S(96),                 by, S(64), S(L_BTN_H), TRUE);
    MoveWindow(g_btnClear,  m + S(166),                by, S(60), S(L_BTN_H), TRUE);
    MoveWindow(g_btnDec,    winW - m - bw * 2 - S(8),  by, bw, bh, TRUE);
    MoveWindow(g_btnEnc,    winW - m - bw,             by, bw, bh, TRUE);

    MoveWindow(g_list,      m, S(L_LIST_Y),
                            winW - m * 2,            S(L_LIST_H), TRUE);

    MoveWindow(g_log,       m, S(L_LOG_Y),
                            winW - m * 2,            S(L_LOG_H), TRUE);

    SendMessageW(g_list, LB_SETITEMHEIGHT, 0, (LPARAM)S(22));

    EnumChildWindows(hWnd, SetFontProc, (LPARAM)g_font);
}

void ApplyWin11RoundedCorners(HWND hWnd) {
    typedef HRESULT (WINAPI *PFN_DwmSetWindowAttribute)(HWND, DWORD, LPCVOID, DWORD);
    HMODULE dwm = LoadLibraryW(L"dwmapi.dll");
    if (!dwm) return;
    auto pfn = (PFN_DwmSetWindowAttribute)GetProcAddress(dwm, "DwmSetWindowAttribute");
    if (pfn) {
        const DWORD DWMWA_WINDOW_CORNER_PREFERENCE = 33;
        const int DWMWCP_ROUND = 2;
        pfn(hWnd, DWMWA_WINDOW_CORNER_PREFERENCE, &DWMWCP_ROUND, sizeof(DWMWCP_ROUND));
    }
    FreeLibrary(dwm);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {

    case WM_CREATE: {
        HDC hdc = GetDC(hWnd);
        g_dpi = GetDeviceCaps(hdc, LOGPIXELSX);
        ReleaseDC(hWnd, hdc);
        if (g_dpi <= 0) g_dpi = 96;

        g_brushBg = CreateSolidBrush(RGB(243, 243, 243));
        CreateFonts();

        g_lbPw = CreateWindowW(L"STATIC", L"密码",
            WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hWnd, NULL, NULL, NULL);
        g_lbRatio = CreateWindowW(L"STATIC", L"加密比例",
            WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hWnd, NULL, NULL, NULL);
        g_lbPct = CreateWindowW(L"STATIC", L"%",
            WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hWnd, NULL, NULL, NULL);

        g_pwEdit = CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
            0, 0, 0, 0, hWnd, (HMENU)ID_PW, NULL, NULL);
        SendMessageW(g_pwEdit, EM_SETLIMITTEXT, 256, 0);

        g_showPw = CreateWindowW(L"BUTTON", L"显示密码",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
            0, 0, 0, 0, hWnd, (HMENU)ID_SHOWPW, NULL, NULL);

        g_ratioEdit = CreateWindowExW(0, L"EDIT", L"25",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_NUMBER | ES_CENTER | ES_AUTOHSCROLL,
            0, 0, 0, 0, hWnd, (HMENU)ID_RATIO, NULL, NULL);
        SendMessageW(g_ratioEdit, EM_SETLIMITTEXT, 3, 0);

        g_btnAdd    = MakeButton(hWnd, ID_ADD,    L"添加文件", BTN_NORMAL,  0,0,0,0);
        g_btnRemove = MakeButton(hWnd, ID_REMOVE, L"移除",     BTN_NORMAL,  0,0,0,0);
        g_btnClear  = MakeButton(hWnd, ID_CLEAR,  L"清空",     BTN_NORMAL,  0,0,0,0);
        g_btnDec    = MakeButton(hWnd, ID_DEC,    L"解密",     BTN_NORMAL,  0,0,0,0);
        g_btnEnc    = MakeButton(hWnd, ID_ENC,    L"加密",     BTN_PRIMARY, 0,0,0,0);

        g_list = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL
            | LBS_NOINTEGRALHEIGHT | LBS_EXTENDEDSEL | LBS_NOTIFY,
            0, 0, 0, 0, hWnd, (HMENU)ID_LIST, NULL, NULL);
        g_oldListProc = (WNDPROC)SetWindowLongPtrW(g_list, GWLP_WNDPROC,
                                                   (LONG_PTR)ListProc);

        g_log = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY
            | WS_VSCROLL | ES_AUTOVSCROLL,
            0, 0, 0, 0, hWnd, (HMENU)ID_LOG, NULL, NULL);

        LayoutAll(hWnd);
        DragAcceptFiles(hWnd, TRUE);
        return 0;
    }

    case WM_DPICHANGED: {
        g_dpi = HIWORD(wParam);
        if (g_dpi <= 0) g_dpi = 96;

        CreateFonts();

        RECT* prc = (RECT*)lParam;
        SetWindowPos(hWnd, NULL,
                     prc->left, prc->top,
                     prc->right - prc->left, prc->bottom - prc->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);

        LayoutAll(hWnd);
        InvalidateRect(hWnd, NULL, TRUE);
        return 0;
    }

    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* dis = (DRAWITEMSTRUCT*)lParam;
        if (dis->CtlType == ODT_BUTTON) {
            PaintButton(dis, FindBtn(dis->hwndItem));
            return TRUE;
        }
        break;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, RGB(243, 243, 243));
        SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)g_brushBg;
    }

    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, RGB(255, 255, 255));
        return (LRESULT)GetStockObject(WHITE_BRUSH);
    }

    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wParam;
        RECT rc; GetClientRect(hWnd, &rc);
        FillRect(hdc, &rc, g_brushBg);
        return 1;
    }

    case WM_DROPFILES: {
        HDROP hDrop = (HDROP)wParam;
        UINT n = DragQueryFileW(hDrop, 0xFFFFFFFF, NULL, 0);
        for (UINT i = 0; i < n; ++i) {
            UINT len = DragQueryFileW(hDrop, i, NULL, 0);
            std::wstring path(len + 1, L'\0');
            DragQueryFileW(hDrop, i, &path[0], len + 1);
            path.resize(len);
            DWORD attr = GetFileAttributesW(path.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY))
                AddFile(path);
        }
        DragFinish(hDrop);
        return 0;
    }

    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case ID_ADD:    OnAddFiles(hWnd); break;
        case ID_REMOVE: OnRemoveSelected(hWnd); break;
        case ID_CLEAR:  SendMessageW(g_list, LB_RESETCONTENT, 0, 0); break;
        case ID_ENC:    OnProcess(hWnd, true); break;
        case ID_DEC:    OnProcess(hWnd, false); break;
        case ID_SHOWPW: {
            bool s = SendMessageW(g_showPw, BM_GETCHECK, 0, 0) == BST_CHECKED;
            SendMessageW(g_pwEdit, EM_SETPASSWORDCHAR, s ? 0 : (WPARAM)0x25CF, 0);
            InvalidateRect(g_pwEdit, NULL, TRUE);
            break;
        }
        case ID_RATIO:
            if (HIWORD(wParam) == EN_KILLFOCUS) {
                wchar_t b[16] = {};
                GetWindowTextW(g_ratioEdit, b, 16);
                int v = _wtoi(b);
                if (v < 1) v = 1;
                if (v > 100) v = 100;
                swprintf(b, 16, L"%d", v);
                SetWindowTextW(g_ratioEdit, b);
            }
            break;
        }
        return 0;
    }

    case WM_DESTROY: {
        if (g_font) DeleteObject(g_font);
        if (g_fontBold) DeleteObject(g_fontBold);
        if (g_brushBg) DeleteObject(g_brushBg);
        PostQuitMessage(0);
        return 0;
    }
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ---------- DPI 感知（全部动态加载，不依赖头文件声明） ----------
void EnableDpiAwareness() {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");

    // 1) Per-Monitor V2 (Win10 1703+)
    if (user32) {
        typedef BOOL (WINAPI *PFN_SetProcessDpiAwarenessContext)(HANDLE);
        auto pfn = (PFN_SetProcessDpiAwarenessContext)
            GetProcAddress(user32, "SetProcessDpiAwarenessContext");
        if (pfn) {
            if (pfn(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) return;
        }
    }

    // 2) Per-Monitor (Win8.1+)
    HMODULE shcore = LoadLibraryW(L"shcore.dll");
    if (shcore) {
        typedef HRESULT (WINAPI *PFN_SetProcessDpiAwareness)(int);
        auto pfn = (PFN_SetProcessDpiAwareness)
            GetProcAddress(shcore, "SetProcessDpiAwareness");
        if (pfn) {
            // PROCESS_PER_MONITOR_DPI_AWARE = 2
            if (pfn(2) == 0) { FreeLibrary(shcore); return; }
        }
        FreeLibrary(shcore);
    }

    // 3) System DPI (Vista+)
    if (user32) {
        typedef BOOL (WINAPI *PFN_SetProcessDPIAware)();
        auto pfn = (PFN_SetProcessDPIAware)
            GetProcAddress(user32, "SetProcessDPIAware");
        if (pfn) { pfn(); return; }
    }
}

int RunGui(HINSTANCE hInstance) {
    EnableDpiAwareness();

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = NULL;
    wc.lpszClassName = L"FileCryptWnd";
    wc.hIcon         = LoadIcon(NULL, IDI_APPLICATION);
    wc.hIconSm       = LoadIcon(NULL, IDI_APPLICATION);
    if (!RegisterClassExW(&wc)) return 1;

    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;

    HDC screen = GetDC(NULL);
    int initDpi = GetDeviceCaps(screen, LOGPIXELSX);
    ReleaseDC(NULL, screen);
    if (initDpi <= 0) initDpi = 96;

    RECT rc = {0, 0, MulDiv(L_WIN_W, initDpi, 96), MulDiv(L_WIN_H, initDpi, 96)};
    AdjustWindowRectEx(&rc, style, FALSE, 0);

    g_hwnd = CreateWindowExW(0, L"FileCryptWnd", L"文件加密工具",
        style, CW_USEDEFAULT, CW_USEDEFAULT,
        rc.right - rc.left, rc.bottom - rc.top,
        NULL, NULL, hInstance, NULL);
    if (!g_hwnd) return 1;

    ApplyWin11RoundedCorners(g_hwnd);

    RECT wr; GetWindowRect(g_hwnd, &wr);
    int ww = wr.right - wr.left, wh = wr.bottom - wr.top;
    RECT scr; SystemParametersInfoW(SPI_GETWORKAREA, 0, &scr, 0);
    int x = scr.left + ((scr.right - scr.left) - ww) / 2;
    int y = scr.top  + ((scr.bottom - scr.top) - wh) / 2;
    SetWindowPos(g_hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);

    ShowWindow(g_hwnd, SW_SHOW);
    UpdateWindow(g_hwnd);
    SetFocus(g_pwEdit);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        if (!IsDialogMessageW(g_hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return (int)msg.wParam;
}

// ============================================================================
//  命令行模式
// ============================================================================
void SetupConsole() {
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    freopen_s(&f, "CONIN$",  "r", stdin);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode)) {
        DWORD w;
        const wchar_t* nl = L"\r\n";
        WriteConsoleW(hOut, nl, 2, &w, NULL);
    }
}

void wout(const std::wstring& s) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode)) {
        DWORD w;
        WriteConsoleW(h, s.c_str(), (DWORD)s.size(), &w, NULL);
    } else {
        int len = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(),
                                      nullptr, 0, nullptr, nullptr);
        std::string u8(len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), &u8[0], len, nullptr, nullptr);
        DWORD w;
        WriteFile(h, u8.data(), (DWORD)u8.size(), &w, NULL);
    }
}
void woutln(const std::wstring& s = L"") { wout(s + L"\r\n"); }

std::wstring ReadPw(const wchar_t* prompt) {
    wout(prompt);
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD oldMode = 0;
    bool isCon = GetConsoleMode(hIn, &oldMode) != 0;
    if (isCon) SetConsoleMode(hIn, oldMode & ~ENABLE_ECHO_INPUT);
    std::wstring pw;
    wchar_t ch = 0;
    while (ReadConsoleW(hIn, &ch, 1, nullptr, NULL)) {
        if (ch == L'\r' || ch == L'\n') break;
        if (ch == L'\b') { if (!pw.empty()) pw.pop_back(); continue; }
        pw.push_back(ch);
    }
    if (isCon) { SetConsoleMode(hIn, oldMode); woutln(); }
    return pw;
}

void PrintUsage() {
    woutln(L"用法:");
    woutln(L"  file_crypt.exe                        启动 GUI");
    woutln(L"  file_crypt.exe enc [-r 25] [-p 密码] 文件...");
    woutln(L"  file_crypt.exe dec [-p 密码] 文件...");
    woutln(L"");
    woutln(L"示例:");
    woutln(L"  file_crypt.exe enc -r 30 secret.docx photo.jpg");
    woutln(L"  file_crypt.exe dec -p mypass data.bin");
}

int RunCli(int argc, wchar_t** argv) {
    SetupConsole();
    if (argc < 2) { PrintUsage(); return 1; }

    std::wstring mode = argv[1];
    bool isEnc;
    if (_wcsicmp(mode.c_str(), L"enc") == 0 || _wcsicmp(mode.c_str(), L"encrypt") == 0)
        isEnc = true;
    else if (_wcsicmp(mode.c_str(), L"dec") == 0 || _wcsicmp(mode.c_str(), L"decrypt") == 0)
        isEnc = false;
    else { woutln(L"未知命令: " + mode); PrintUsage(); return 1; }

    double ratio = 0.25;
    std::wstring password;
    bool hasPw = false;
    std::vector<std::wstring> files;

    int i = 2;
    while (i < argc) {
        std::wstring a = argv[i];
        if (a == L"-r" || a == L"--ratio") {
            if (i + 1 >= argc) { woutln(L"错误: -r 需要参数"); return 1; }
            int v = _wtoi(argv[i + 1]);
            if (v < 1) v = 1;
            if (v > 100) v = 100;
            ratio = v / 100.0;
            i += 2;
        } else if (a == L"-p" || a == L"--password") {
            if (i + 1 >= argc) { woutln(L"错误: -p 需要参数"); return 1; }
            password = argv[i + 1]; hasPw = true; i += 2;
        } else if (a == L"-h" || a == L"--help") {
            PrintUsage(); return 0;
        } else if (!a.empty() && a[0] == L'-') {
            woutln(L"未知参数: " + a); PrintUsage(); return 1;
        } else {
            files.push_back(a); ++i;
        }
    }
    if (files.empty()) { woutln(L"错误: 没有文件"); PrintUsage(); return 1; }

    if (!hasPw) {
        password = ReadPw(L"请输入密码: ");
        if (password.empty()) { woutln(L"错误: 密码为空"); return 1; }
        if (isEnc) {
            std::wstring confirm = ReadPw(L"再次输入密码确认: ");
            if (confirm != password) { woutln(L"错误: 两次密码不一致"); return 1; }
        }
    }
    std::string pwUtf8 = wideToUtf8(password);

    int ok = 0;
    for (auto& p : files) {
        std::wstring err;
        bool r = isEnc ? encryptFileW(p, pwUtf8, ratio, err)
                       : decryptFileW(p, pwUtf8, err);
        if (r) { ++ok; woutln((isEnc ? L"[OK] 已加密: " : L"[OK] 已解密: ") + p); }
        else   { woutln(L"[失败] " + p + L"  → " + err); }
    }
    woutln(L"完成: " + std::to_wstring(ok) + L" / " +
           std::to_wstring(files.size()) + L" 个文件");
    return ok == (int)files.size() ? 0 : 2;
}

// ============================================================================
//  入口
// ============================================================================
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc < 2 || _wcsicmp(argv[1], L"gui") == 0) {
        if (argv) LocalFree(argv);
        return RunGui(hInstance);
    }
    int ret = RunCli(argc, argv);
    if (argv) LocalFree(argv);
    return ret;
}