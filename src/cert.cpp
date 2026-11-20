// language: C++, file: cert.cpp, target: Windows 11, MSVC
// *X.509 parse via Crypt32. PEM/DER. Signature, validity, KU/EKU, basic constraints.*
#define WIN32_LEAN_AND_MEAN
#include "cert.hpp"

#include <windows.h>
#include <wincrypt.h>

#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace {

constexpr std::size_t kMaxCertBytes = 1 * 1024 * 1024;

struct CertContextDeleter {
    void operator()(PCCERT_CONTEXT p) const noexcept {
        if (p) CertFreeCertificateContext(p);
    }
};
using UniqueCert = std::unique_ptr<const CERT_CONTEXT, CertContextDeleter>;

struct LocalDeleter {
    void operator()(void* p) const noexcept {
        if (p) LocalFree(p);
    }
};

std::wstring hex_of(const BYTE* p, DWORD n, bool colon) {
    static const wchar_t* h = L"0123456789ABCDEF";
    std::wstring s;
    s.reserve(n * (colon ? 3u : 2u));
    for (DWORD i = 0; i < n; ++i) {
        if (colon && i) s.push_back(L':');
        s.push_back(h[p[i] >> 4]);
        s.push_back(h[p[i] & 0xF]);
    }
    return s;
}

std::wstring name_blob(PCCERT_CONTEXT ctx, DWORD type, DWORD flag) {
    DWORD n = CertGetNameStringW(ctx, type, flag, nullptr, nullptr, 0);
    if (n <= 1) return L"(none)";
    std::wstring s(n, L'\0');
    CertGetNameStringW(ctx, type, flag, nullptr, s.data(), n);
    if (!s.empty() && s.back() == L'\0') s.pop_back();
    return s;
}

std::wstring filetime_str(const FILETIME& ft) {
    SYSTEMTIME st{};
    FILETIME loc{};
    FileTimeToLocalFileTime(&ft, &loc);
    FileTimeToSystemTime(&loc, &st);
    wchar_t buf[64];
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::wstring oid_name(const char* oid) {
    if (!oid) return L"(none)";
    PCCRYPT_OID_INFO info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, const_cast<char*>(oid), 0);
    if (info && info->pwszName) {
        std::wstring n = info->pwszName;
        n += L"  (";
        for (const char* p = oid; *p; ++p) n.push_back(static_cast<wchar_t>(*p));
        n += L")";
        return n;
    }
    std::wstring n;
    for (const char* p = oid; *p; ++p) n.push_back(static_cast<wchar_t>(*p));
    return n;
}

std::wstring oid_short(const char* oid) {
    if (!oid) return L"(none)";
    PCCRYPT_OID_INFO info = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, const_cast<char*>(oid), 0);
    if (info && info->pwszName) return info->pwszName;
    std::wstring n;
    for (const char* p = oid; *p; ++p) n.push_back(static_cast<wchar_t>(*p));
    return n;
}

bool load_bytes(const std::wstring& path, std::vector<BYTE>& out, std::wstring& err) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        err = L"cannot read file";
        return false;
    }
    f.seekg(0, std::ios::end);
    const std::streamoff off = f.tellg();
    if (off < 0) {
        err = L"cannot size file";
        return false;
    }
    if (static_cast<std::uintmax_t>(off) > kMaxCertBytes) {
        err = L"file too large";
        return false;
    }
    const auto n = static_cast<std::size_t>(off);
    f.seekg(0);
    out.resize(n);
    if (n && !f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(n))) {
        err = L"cannot read file";
        return false;
    }
    return true;
}

UniqueCert parse_encoded(const std::vector<BYTE>& raw) {
    if (raw.empty()) return {};
    PCCERT_CONTEXT ctx = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, raw.data(), static_cast<DWORD>(raw.size()));
    if (ctx) return UniqueCert(ctx);

    const DWORD flags[] = {CRYPT_STRING_BASE64HEADER, CRYPT_STRING_BASE64_ANY};
    for (DWORD flag : flags) {
        DWORD skip = 0, n = 0;
        if (!CryptStringToBinaryA(reinterpret_cast<const char*>(raw.data()), static_cast<DWORD>(raw.size()),
                                  flag, nullptr, &n, &skip, nullptr) ||
            n == 0 || n > kMaxCertBytes) {
            continue;
        }
        std::vector<BYTE> der(n);
        if (!CryptStringToBinaryA(reinterpret_cast<const char*>(raw.data()), static_cast<DWORD>(raw.size()),
                                  flag, der.data(), &n, &skip, nullptr)) {
            continue;
        }
        ctx = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der.data(), n);
        if (ctx) return UniqueCert(ctx);
    }
    return {};
}

std::wstring validity_vs_now(const FILETIME& not_before, const FILETIME& not_after) {
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    if (CompareFileTime(&now, &not_before) < 0) return L"not yet valid";
    if (CompareFileTime(&now, &not_after) > 0) return L"expired";
    return L"valid";
}

bool verify_self_signature(PCCERT_CONTEXT ctx) {
    return CryptVerifyCertificateSignatureEx(
               0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, const_cast<PCERT_CONTEXT>(ctx),
               CRYPT_VERIFY_CERT_SIGN_ISSUER_PUBKEY, &ctx->pCertInfo->SubjectPublicKeyInfo, 0, nullptr) !=
           FALSE;
}

std::wstring key_usage_text(PCCERT_CONTEXT ctx) {
    PCERT_EXTENSION ext =
        CertFindExtension(szOID_KEY_USAGE, ctx->pCertInfo->cExtension, ctx->pCertInfo->rgExtension);
    if (!ext) return L"(none)";
    PCRYPT_BIT_BLOB bits = nullptr;
    DWORD cb = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_KEY_USAGE, ext->Value.pbData, ext->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, nullptr, &bits, &cb) ||
        !bits) {
        return L"(present, decode failed)";
    }
    std::unique_ptr<void, LocalDeleter> hold(bits);
    BYTE b = (bits->cbData > 0 && bits->pbData) ? bits->pbData[0] : 0;
    struct Flag {
        BYTE mask;
        const wchar_t* name;
    };
    constexpr Flag kFlags[] = {
        {CERT_DIGITAL_SIGNATURE_KEY_USAGE, L"digitalSignature"},
        {CERT_NON_REPUDIATION_KEY_USAGE, L"nonRepudiation"},
        {CERT_KEY_ENCIPHERMENT_KEY_USAGE, L"keyEncipherment"},
        {CERT_DATA_ENCIPHERMENT_KEY_USAGE, L"dataEncipherment"},
        {CERT_KEY_AGREEMENT_KEY_USAGE, L"keyAgreement"},
        {CERT_KEY_CERT_SIGN_KEY_USAGE, L"keyCertSign"},
        {CERT_OFFLINE_CRL_SIGN_KEY_USAGE, L"cRLSign"},
        {CERT_ENCIPHER_ONLY_KEY_USAGE, L"encipherOnly"},
    };
    std::wstring out;
    for (const auto& f : kFlags) {
        if (b & f.mask) {
            if (!out.empty()) out += L", ";
            out += f.name;
        }
    }
    if (bits->cbData > 1 && bits->pbData && (bits->pbData[1] & CERT_DECIPHER_ONLY_KEY_USAGE)) {
        if (!out.empty()) out += L", ";
        out += L"decipherOnly";
    }
    return out.empty() ? L"(none)" : out;
}

std::wstring eku_text(PCCERT_CONTEXT ctx) {
    PCERT_EXTENSION ext =
        CertFindExtension(szOID_ENHANCED_KEY_USAGE, ctx->pCertInfo->cExtension, ctx->pCertInfo->rgExtension);
    if (!ext) return L"(none)";
    PCERT_ENHKEY_USAGE usage = nullptr;
    DWORD cb = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, ext->Value.pbData, ext->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, nullptr, &usage, &cb) ||
        !usage) {
        return L"(present, decode failed)";
    }
    std::unique_ptr<void, LocalDeleter> hold(usage);
    std::wstring out;
    for (DWORD i = 0; i < usage->cUsageIdentifier; ++i) {
        if (!out.empty()) out += L", ";
        out += oid_short(usage->rgpszUsageIdentifier[i]);
    }
    return out.empty() ? L"(none)" : out;
}

void fill_basic_constraints(PCCERT_CONTEXT ctx, CertInfo& info) {
    PCERT_EXTENSION ext =
        CertFindExtension(szOID_BASIC_CONSTRAINTS2, ctx->pCertInfo->cExtension, ctx->pCertInfo->rgExtension);
    if (!ext) {
        info.basic_constraints_present = false;
        info.ca = false;
        info.basic_constraints = L"(none)";
        return;
    }
    PCERT_BASIC_CONSTRAINTS2_INFO bc = nullptr;
    DWORD cb = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2, ext->Value.pbData, ext->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, nullptr, &bc, &cb) ||
        !bc) {
        info.basic_constraints_present = true;
        info.ca = false;
        info.basic_constraints = L"(present, decode failed)";
        return;
    }
    std::unique_ptr<void, LocalDeleter> hold(bc);
    info.basic_constraints_present = true;
    info.ca = bc->fCA != FALSE;
    info.basic_constraints = info.ca ? L"CA=yes" : L"CA=no";
    if (bc->fPathLenConstraint) {
        info.basic_constraints += L", pathLen=";
        info.basic_constraints += std::to_wstring(bc->dwPathLenConstraint);
    }
}

std::wstring san_list(PCCERT_CONTEXT ctx) {
    PCERT_EXTENSION ext =
        CertFindExtension(szOID_SUBJECT_ALT_NAME2, ctx->pCertInfo->cExtension, ctx->pCertInfo->rgExtension);
    if (!ext) ext = CertFindExtension(szOID_SUBJECT_ALT_NAME, ctx->pCertInfo->cExtension, ctx->pCertInfo->rgExtension);
    if (!ext) return L"(none)";
    PCERT_ALT_NAME_INFO alt = nullptr;
    DWORD cb = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, szOID_SUBJECT_ALT_NAME2, ext->Value.pbData, ext->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, nullptr, &alt, &cb) ||
        !alt) {
        return L"(present, decode failed)";
    }
    std::unique_ptr<void, LocalDeleter> hold(alt);
    std::wstring out;
    for (DWORD i = 0; i < alt->cAltEntry; ++i) {
        if (!out.empty()) out += L", ";
        auto& e = alt->rgAltEntry[i];
        if (e.dwAltNameChoice == CERT_ALT_NAME_DNS_NAME && e.pwszDNSName)
            out += std::wstring(L"DNS:") + e.pwszDNSName;
        else if (e.dwAltNameChoice == CERT_ALT_NAME_RFC822_NAME && e.pwszRfc822Name)
            out += std::wstring(L"email:") + e.pwszRfc822Name;
        else if (e.dwAltNameChoice == CERT_ALT_NAME_URL && e.pwszURL)
            out += std::wstring(L"URI:") + e.pwszURL;
        else
            out += L"(other)";
    }
    return out.empty() ? L"(none)" : out;
}

void push_row(CertInfo& info, const wchar_t* k, const std::wstring& v) {
    info.rows.push_back({k, v});
}

}  // namespace

CertInfo parse_cert_bytes(const std::vector<unsigned char>& raw, const std::wstring& path) {
    CertInfo info;
    info.path = path;
    UniqueCert ctx = parse_encoded(raw);
    if (!ctx) {
        info.error = L"not an X.509 certificate (PEM/DER)";
        return info;
    }

    BYTE sha1[20]{};
    DWORD n1 = 20;
    CertGetCertificateContextProperty(ctx.get(), CERT_SHA1_HASH_PROP_ID, sha1, &n1);

    BYTE sha256[32]{};
    DWORD n256 = 32;
    CryptHashCertificate2(L"SHA256", 0, nullptr, ctx->pbCertEncoded, ctx->cbCertEncoded, sha256, &n256);

    info.self_issued =
        CertCompareCertificateName(X509_ASN_ENCODING, &ctx->pCertInfo->Subject, &ctx->pCertInfo->Issuer) != FALSE;
    info.self_signature_valid = verify_self_signature(ctx.get());
    info.self_signed = info.self_issued && info.self_signature_valid;
    if (!info.self_issued)
        info.self_signature = L"not self-issued";
    else
        info.self_signature = info.self_signature_valid ? L"valid" : L"invalid";

    info.subject = name_blob(ctx.get(), CERT_NAME_SIMPLE_DISPLAY_TYPE, 0);
    info.subject_dn = name_blob(ctx.get(), CERT_NAME_RDN_TYPE, 0);
    info.issuer = name_blob(ctx.get(), CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG);
    info.issuer_dn = name_blob(ctx.get(), CERT_NAME_RDN_TYPE, CERT_NAME_ISSUER_FLAG);
    info.serial = hex_of(ctx->pCertInfo->SerialNumber.pbData, ctx->pCertInfo->SerialNumber.cbData, true);
    info.not_before = filetime_str(ctx->pCertInfo->NotBefore);
    info.not_after = filetime_str(ctx->pCertInfo->NotAfter);
    info.validity = validity_vs_now(ctx->pCertInfo->NotBefore, ctx->pCertInfo->NotAfter);
    info.signature_alg = oid_name(ctx->pCertInfo->SignatureAlgorithm.pszObjId);
    info.key_type = oid_name(ctx->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
    info.key_bits = CertGetPublicKeyLength(X509_ASN_ENCODING, &ctx->pCertInfo->SubjectPublicKeyInfo);
    info.key_usage = key_usage_text(ctx.get());
    info.eku = eku_text(ctx.get());
    fill_basic_constraints(ctx.get(), info);
    info.san = san_list(ctx.get());
    info.thumbprint_sha1 = hex_of(sha1, 20, true);
    info.thumbprint_sha256 = hex_of(sha256, n256, true);
    info.encoded_bytes = ctx->cbCertEncoded;

    push_row(info, L"file", info.path);
    push_row(info, L"subject", info.subject);
    push_row(info, L"subject DN", info.subject_dn);
    push_row(info, L"issuer", info.issuer);
    push_row(info, L"issuer DN", info.issuer_dn);
    push_row(info, L"self-issued", info.self_issued ? L"yes" : L"no");
    push_row(info, L"self-signature", info.self_signature);
    push_row(info, L"self-signed", info.self_signed ? L"yes" : L"no");
    push_row(info, L"serial", info.serial);
    push_row(info, L"not before", info.not_before);
    push_row(info, L"not after", info.not_after);
    push_row(info, L"validity", info.validity);
    push_row(info, L"signature", info.signature_alg);
    push_row(info, L"public key", info.key_type + L"  " + std::to_wstring(info.key_bits) + L" bit");
    push_row(info, L"key usage", info.key_usage);
    push_row(info, L"EKU", info.eku);
    push_row(info, L"basic constraints", info.basic_constraints);
    push_row(info, L"SAN", info.san);
    push_row(info, L"thumbprint SHA-1", info.thumbprint_sha1);
    push_row(info, L"thumbprint SHA-256", info.thumbprint_sha256);
    push_row(info, L"encoded", std::to_wstring(info.encoded_bytes) + L" bytes");

    info.ok = true;
    return info;
}

CertInfo parse_cert_file(const std::wstring& path) {
    CertInfo info;
    info.path = path;
    std::vector<BYTE> raw;
    if (!load_bytes(path, raw, info.error)) return info;
    return parse_cert_bytes(raw, path);
}
