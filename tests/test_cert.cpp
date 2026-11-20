// language: C++, file: test_cert.cpp, target: Windows 11, MSVC
// *Console tests for Crypt32 parse. No Win32 UI.*
#define WIN32_LEAN_AND_MEAN
#include "cert.hpp"

#include <windows.h>

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#ifndef SAMPLE_PEM_PATH
#error SAMPLE_PEM_PATH required
#endif
#ifndef GARBAGE_PATH
#error GARBAGE_PATH required
#endif

static int g_fails = 0;

static std::wstring utf8_to_wide(const char* p) {
    int n = MultiByteToWideChar(CP_UTF8, 0, p, -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring w(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, p, -1, w.data(), n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

static void expect(bool cond, const char* name) {
    if (!cond) {
        std::fprintf(stderr, "FAIL %s\n", name);
        ++g_fails;
    } else {
        std::printf("ok   %s\n", name);
    }
}

static bool contains(const std::wstring& hay, const wchar_t* needle) {
    return hay.find(needle) != std::wstring::npos;
}

int wmain() {
    const std::wstring pem = utf8_to_wide(SAMPLE_PEM_PATH);
    const std::wstring garbage = utf8_to_wide(GARBAGE_PATH);

    CertInfo good = parse_cert_file(pem);
    expect(good.ok, "example.pem parses");
    expect(contains(good.subject, L"cert-lens.example"), "subject CN");
    expect(contains(good.subject_dn, L"Portfolio"), "subject O=Portfolio");
    expect(!contains(good.subject_dn, L"University") && !contains(good.issuer_dn, L"University"),
           "no fake university");
    expect(good.self_issued, "self-issued names");
    expect(good.self_signature_valid, "self-signature CryptVerify");
    expect(good.self_signed, "self-signed = issued + signature");
    expect(good.validity == L"valid", "validity vs now");
    expect(good.key_bits == 2048, "RSA 2048");
    expect(contains(good.key_usage, L"digitalSignature"), "KU digitalSignature");
    expect(contains(good.key_usage, L"keyEncipherment"), "KU keyEncipherment");
    expect(contains(good.eku, L"Server Authentication") || contains(good.eku, L"1.3.6.1.5.5.7.3.1"),
           "EKU serverAuth");
    expect(contains(good.eku, L"Client Authentication") || contains(good.eku, L"1.3.6.1.5.5.7.3.2"),
           "EKU clientAuth");
    expect(!good.basic_constraints_present, "no basicConstraints on leaf sample");
    expect(!good.ca, "sample is not a CA");
    expect(good.basic_constraints == L"(none)", "BC none");
    expect(contains(good.san, L"cert-lens.example"), "SAN DNS example");
    expect(contains(good.san, L"localhost"), "SAN DNS localhost");
    expect(good.encoded_bytes > 400, "encoded size");
    expect(!good.thumbprint_sha1.empty() && !good.thumbprint_sha256.empty(), "thumbprints");

    std::ifstream der_check(utf8_to_wide(SAMPLE_CER_PATH), std::ios::binary);
    expect(static_cast<bool>(der_check), "example.cer exists");
    if (der_check) {
        CertInfo cer = parse_cert_file(utf8_to_wide(SAMPLE_CER_PATH));
        expect(cer.ok, "example.cer parses");
        expect(cer.thumbprint_sha256 == good.thumbprint_sha256, "PEM and CER same SHA-256");
    }

    CertInfo bad = parse_cert_file(garbage);
    expect(!bad.ok, "garbage file fails");
    expect(bad.error.find(L"X.509") != std::wstring::npos || bad.error.find(L"cannot") != std::wstring::npos,
           "garbage error set");

    std::vector<unsigned char> junk{0x00, 0x01, 0x02, 0x03, 0xff};
    CertInfo junk_info = parse_cert_bytes(junk, L"(memory)");
    expect(!junk_info.ok, "garbage bytes fail");

    if (g_fails) {
        std::fprintf(stderr, "%d failed\n", g_fails);
        return 1;
    }
    std::printf("all passed\n");
    return 0;
}
