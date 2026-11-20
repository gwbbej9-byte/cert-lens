#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct CertField {
    std::wstring key;
    std::wstring value;
};

struct CertInfo {
    bool ok = false;
    std::wstring error;
    std::vector<CertField> rows;

    std::wstring path;
    std::wstring subject;
    std::wstring subject_dn;
    std::wstring issuer;
    std::wstring issuer_dn;
    bool self_issued = false;
    bool self_signed = false;
    bool self_signature_valid = false;
    std::wstring self_signature;
    std::wstring serial;
    std::wstring not_before;
    std::wstring not_after;
    std::wstring validity;
    std::wstring signature_alg;
    std::wstring key_type;
    std::uint32_t key_bits = 0;
    std::wstring key_usage;
    std::wstring eku;
    std::wstring basic_constraints;
    bool ca = false;
    bool basic_constraints_present = false;
    std::wstring san;
    std::wstring thumbprint_sha1;
    std::wstring thumbprint_sha256;
    std::uint32_t encoded_bytes = 0;
};

CertInfo parse_cert_file(const std::wstring& path);
CertInfo parse_cert_bytes(const std::vector<unsigned char>& raw, const std::wstring& path);
