#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <cctype>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/xts.h>

struct Options {
    std::string command;
    std::string mode;

    std::string text;
    std::string cipher_hex;

    std::string key_hex;
    std::string iv_hex;
    std::string nonce_hex;
    std::string tag_hex;
    std::string aad_text;

    std::string in_file;
    std::string out_file;

    bool allow_ecb = false;
    bool aead = false;
};

struct Result {
    std::vector<unsigned char> data;
    std::vector<unsigned char> iv_or_nonce;
    std::vector<unsigned char> tag;
};

static std::string lower_str(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

static void usage() {
    std::cout << "Usage:\n";
    std::cout << "  aestool encrypt --mode cbc --key-hex HEX --text \"message\"\n";
    std::cout << "  aestool decrypt --mode cbc --key-hex HEX --iv IVHEX --cipher-hex CTHEX\n\n";

    std::cout << "  aestool encrypt --mode gcm --aead --key-hex HEX --aad-text \"aad\" --text \"message\"\n";
    std::cout << "  aestool decrypt --mode gcm --aead --key-hex HEX --nonce NONCEHEX --aad-text \"aad\" --cipher-hex CTHEX --tag TAGHEX\n\n";

    std::cout << "Modes: ecb, cbc, cfb, ofb, ctr, gcm, ccm, xts\n";
}

static bool parse_args(int argc, char* argv[], Options& opt) {
    if (argc < 2) {
        return false;
    }

    opt.command = lower_str(argv[1]);

    if (opt.command != "encrypt" && opt.command != "decrypt") {
        return false;
    }

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];

        if (a == "--mode" && i + 1 < argc) {
            opt.mode = lower_str(argv[++i]);
        } else if (a == "--text" && i + 1 < argc) {
            opt.text = argv[++i];
        } else if (a == "--cipher-hex" && i + 1 < argc) {
            opt.cipher_hex = argv[++i];
        } else if (a == "--key-hex" && i + 1 < argc) {
            opt.key_hex = argv[++i];
        } else if (a == "--iv" && i + 1 < argc) {
            opt.iv_hex = argv[++i];
        } else if (a == "--nonce" && i + 1 < argc) {
            opt.nonce_hex = argv[++i];
        } else if (a == "--tag" && i + 1 < argc) {
            opt.tag_hex = argv[++i];
        } else if (a == "--aad-text" && i + 1 < argc) {
            opt.aad_text = argv[++i];
        } else if (a == "--in" && i + 1 < argc) {
            opt.in_file = argv[++i];
        } else if (a == "--out" && i + 1 < argc) {
            opt.out_file = argv[++i];
        } else if (a == "--allow-ecb") {
            opt.allow_ecb = true;
        } else if (a == "--aead") {
            opt.aead = true;
        } else {
            std::cerr << "Invalid or missing argument: " << a << "\n";
            return false;
        }
    }

    return !(opt.mode.empty() || opt.key_hex.empty());
}

static std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::string decoded;

    CryptoPP::StringSource ss(
        hex,
        true,
        new CryptoPP::HexDecoder(
            new CryptoPP::StringSink(decoded)
        )
    );

    return std::vector<unsigned char>(decoded.begin(), decoded.end());
}

static std::string bytes_to_hex(const std::vector<unsigned char>& data) {
    std::string encoded;

    CryptoPP::StringSource ss(
        data.data(),
        data.size(),
        true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded),
            false
        )
    );

    return encoded;
}

static std::vector<unsigned char> text_to_bytes(const std::string& s) {
    return std::vector<unsigned char>(s.begin(), s.end());
}

static std::string bytes_to_text(const std::vector<unsigned char>& v) {
    return std::string(v.begin(), v.end());
}

static std::vector<unsigned char> random_bytes(size_t n) {
    std::vector<unsigned char> out(n);
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(out.data(), out.size());
    return out;
}

static std::vector<unsigned char> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);

    if (!f) {
        throw std::runtime_error("Cannot open input file: " + path);
    }

    return std::vector<unsigned char>(
        std::istreambuf_iterator<char>(f),
        std::istreambuf_iterator<char>()
    );
}

static void write_file(const std::string& path, const std::vector<unsigned char>& data) {
    std::ofstream f(path, std::ios::binary);

    if (!f) {
        throw std::runtime_error("Cannot open output file: " + path);
    }

    f.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

static bool supported_mode(const std::string& mode) {
    return mode == "ecb" ||
           mode == "cbc" ||
           mode == "cfb" ||
           mode == "ofb" ||
           mode == "ctr" ||
           mode == "gcm" ||
           mode == "ccm" ||
           mode == "xts";
}

static bool is_aead(const std::string& mode) {
    return mode == "gcm" || mode == "ccm";
}

static bool uses_iv(const std::string& mode) {
    return mode == "cbc" ||
           mode == "cfb" ||
           mode == "ofb" ||
           mode == "ctr" ||
           mode == "xts";
}

static bool uses_nonce(const std::string& mode) {
    return mode == "gcm" || mode == "ccm";
}

static void check_key(const std::string& mode, const std::vector<unsigned char>& key) {
    if (mode == "xts") {
        if (!(key.size() == 32 || key.size() == 64)) {
            throw std::runtime_error("XTS key must be 32 or 64 bytes.");
        }
        return;
    }

    if (!(key.size() == 16 || key.size() == 24 || key.size() == 32)) {
        throw std::runtime_error("AES key must be 16, 24, or 32 bytes.");
    }
}

static void check_iv16(const std::vector<unsigned char>& iv, const std::string& mode) {
    if (iv.size() != 16) {
        throw std::runtime_error(mode + " requires 16-byte IV/tweak.");
    }
}

static void check_nonce12(const std::vector<unsigned char>& nonce, const std::string& mode) {
    if (nonce.size() != 12) {
        throw std::runtime_error(mode + " requires 12-byte nonce.");
    }
}

static Result encrypt_data(
    const std::string& mode,
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key,
    std::vector<unsigned char> iv_or_nonce,
    const std::vector<unsigned char>& aad
) {
    check_key(mode, key);

    Result r;
    std::string out;

    if (mode == "ecb") {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKey(key.data(), key.size());

        CryptoPP::StringSource ss(
            plaintext.data(),
            plaintext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(out)
            )
        );

        r.data.assign(out.begin(), out.end());
        return r;
    }

    if (mode == "cbc") {
        if (iv_or_nonce.empty()) iv_or_nonce = random_bytes(16);
        check_iv16(iv_or_nonce, "CBC");

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());

        CryptoPP::StringSource ss(
            plaintext.data(),
            plaintext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(out)
            )
        );

        r.data.assign(out.begin(), out.end());
        r.iv_or_nonce = iv_or_nonce;
        return r;
    }

    if (mode == "cfb") {
        if (iv_or_nonce.empty()) iv_or_nonce = random_bytes(16);
        check_iv16(iv_or_nonce, "CFB");

        CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());

        CryptoPP::StringSource ss(
            plaintext.data(),
            plaintext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(out)
            )
        );

        r.data.assign(out.begin(), out.end());
        r.iv_or_nonce = iv_or_nonce;
        return r;
    }

    if (mode == "ofb") {
        if (iv_or_nonce.empty()) iv_or_nonce = random_bytes(16);
        check_iv16(iv_or_nonce, "OFB");

        CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());

        CryptoPP::StringSource ss(
            plaintext.data(),
            plaintext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(out)
            )
        );

        r.data.assign(out.begin(), out.end());
        r.iv_or_nonce = iv_or_nonce;
        return r;
    }

    if (mode == "ctr") {
        if (iv_or_nonce.empty()) iv_or_nonce = random_bytes(16);
        check_iv16(iv_or_nonce, "CTR");

        CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());

        CryptoPP::StringSource ss(
            plaintext.data(),
            plaintext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(out)
            )
        );

        r.data.assign(out.begin(), out.end());
        r.iv_or_nonce = iv_or_nonce;
        return r;
    }

    if (mode == "gcm") {
        if (iv_or_nonce.empty()) iv_or_nonce = random_bytes(12);
        check_nonce12(iv_or_nonce, "GCM");

        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());

        std::string cipher_tag;

        CryptoPP::AuthenticatedEncryptionFilter ef(
            enc,
            new CryptoPP::StringSink(cipher_tag),
            false,
            16
        );

        if (!aad.empty()) {
            ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
            ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        }

        ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext.data(), plaintext.size());
        ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        r.data.assign(cipher_tag.begin(), cipher_tag.end() - 16);
        r.tag.assign(cipher_tag.end() - 16, cipher_tag.end());
        r.iv_or_nonce = iv_or_nonce;
        return r;
    }

    if (mode == "ccm") {
        if (iv_or_nonce.empty()) iv_or_nonce = random_bytes(12);
        check_nonce12(iv_or_nonce, "CCM");

        CryptoPP::CCM<CryptoPP::AES, 16>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());
        enc.SpecifyDataLengths(aad.size(), plaintext.size(), 0);

        std::string cipher_tag;

        CryptoPP::AuthenticatedEncryptionFilter ef(
            enc,
            new CryptoPP::StringSink(cipher_tag),
            false,
            16
        );

        if (!aad.empty()) {
            ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
            ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        }

        ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, plaintext.data(), plaintext.size());
        ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        r.data.assign(cipher_tag.begin(), cipher_tag.end() - 16);
        r.tag.assign(cipher_tag.end() - 16, cipher_tag.end());
        r.iv_or_nonce = iv_or_nonce;
        return r;
    }

    if (mode == "xts") {
        if (iv_or_nonce.empty()) iv_or_nonce = random_bytes(16);
        check_iv16(iv_or_nonce, "XTS");

        if (plaintext.size() < 16) {
            throw std::runtime_error("XTS requires plaintext length at least 16 bytes.");
        }

        CryptoPP::XTS_Mode<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());

        CryptoPP::StringSource ss(
            plaintext.data(),
            plaintext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                enc,
                new CryptoPP::StringSink(out),
                CryptoPP::StreamTransformationFilter::NO_PADDING
            )
        );

        r.data.assign(out.begin(), out.end());
        r.iv_or_nonce = iv_or_nonce;
        return r;
    }

    throw std::runtime_error("Unsupported mode: " + mode);
}

static Result decrypt_data(
    const std::string& mode,
    const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv_or_nonce,
    const std::vector<unsigned char>& aad,
    const std::vector<unsigned char>& tag
) {
    check_key(mode, key);

    Result r;
    std::string out;

    if (mode == "ecb") {
        CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKey(key.data(), key.size());

        CryptoPP::StringSource ss(
            ciphertext.data(),
            ciphertext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(out)
            )
        );

        r.data.assign(out.begin(), out.end());
        return r;
    }

    if (mode == "cbc") {
        check_iv16(iv_or_nonce, "CBC");

        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());

        CryptoPP::StringSource ss(
            ciphertext.data(),
            ciphertext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(out)
            )
        );

        r.data.assign(out.begin(), out.end());
        return r;
    }

    if (mode == "cfb") {
        check_iv16(iv_or_nonce, "CFB");

        CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());

        CryptoPP::StringSource ss(
            ciphertext.data(),
            ciphertext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(out)
            )
        );

        r.data.assign(out.begin(), out.end());
        return r;
    }

    if (mode == "ofb") {
        check_iv16(iv_or_nonce, "OFB");

        CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());

        CryptoPP::StringSource ss(
            ciphertext.data(),
            ciphertext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(out)
            )
        );

        r.data.assign(out.begin(), out.end());
        return r;
    }

    if (mode == "ctr") {
        check_iv16(iv_or_nonce, "CTR");

        CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());

        CryptoPP::StringSource ss(
            ciphertext.data(),
            ciphertext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(out)
            )
        );

        r.data.assign(out.begin(), out.end());
        return r;
    }

    if (mode == "gcm") {
        check_nonce12(iv_or_nonce, "GCM");

        if (tag.size() != 16) {
            throw std::runtime_error("GCM tag must be 16 bytes.");
        }

        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());

        std::string cipher_tag(ciphertext.begin(), ciphertext.end());
        cipher_tag.append(tag.begin(), tag.end());

        CryptoPP::AuthenticatedDecryptionFilter df(
            dec,
            new CryptoPP::StringSink(out),
            CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            16
        );

        if (!aad.empty()) {
            df.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
            df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        }

        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, reinterpret_cast<const unsigned char*>(cipher_tag.data()), cipher_tag.size());
        df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        r.data.assign(out.begin(), out.end());
        return r;
    }

    if (mode == "ccm") {
        check_nonce12(iv_or_nonce, "CCM");

        if (tag.size() != 16) {
            throw std::runtime_error("CCM tag must be 16 bytes.");
        }

        CryptoPP::CCM<CryptoPP::AES, 16>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());
        dec.SpecifyDataLengths(aad.size(), ciphertext.size(), 0);

        std::string cipher_tag(ciphertext.begin(), ciphertext.end());
        cipher_tag.append(tag.begin(), tag.end());

        CryptoPP::AuthenticatedDecryptionFilter df(
            dec,
            new CryptoPP::StringSink(out),
            CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            16
        );

        if (!aad.empty()) {
            df.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
            df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        }

        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, reinterpret_cast<const unsigned char*>(cipher_tag.data()), cipher_tag.size());
        df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);

        r.data.assign(out.begin(), out.end());
        return r;
    }

    if (mode == "xts") {
        check_iv16(iv_or_nonce, "XTS");

        if (ciphertext.size() < 16) {
            throw std::runtime_error("XTS requires ciphertext length at least 16 bytes.");
        }

        CryptoPP::XTS_Mode<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv_or_nonce.data(), iv_or_nonce.size());

        CryptoPP::StringSource ss(
            ciphertext.data(),
            ciphertext.size(),
            true,
            new CryptoPP::StreamTransformationFilter(
                dec,
                new CryptoPP::StringSink(out),
                CryptoPP::StreamTransformationFilter::NO_PADDING
            )
        );

        r.data.assign(out.begin(), out.end());
        return r;
    }

    throw std::runtime_error("Unsupported mode: " + mode);
}

int main(int argc, char* argv[]) {
    try {
        Options opt;

        if (!parse_args(argc, argv, opt)) {
            usage();
            return 1;
        }

        std::cout << "--- [aestool fresh build] ---\n";
        std::cout << "Crypto++ version: " << CRYPTOPP_VERSION << "\n";

        if (!supported_mode(opt.mode)) {
            throw std::runtime_error("Unsupported mode: " + opt.mode);
        }

        if (opt.mode == "ecb" && !opt.allow_ecb) {
            std::cout << "[WARNING] ECB mode is insecure.\n";
            std::cout << "Blocked by default. Use --allow-ecb to override.\n";
            return 1;
        }

        if (is_aead(opt.mode) && !opt.aead) {
            throw std::runtime_error("GCM/CCM requires --aead flag.");
        }

        std::vector<unsigned char> key = hex_to_bytes(opt.key_hex);
        std::vector<unsigned char> aad = text_to_bytes(opt.aad_text);

        std::vector<unsigned char> iv_or_nonce;

        if (uses_iv(opt.mode) && !opt.iv_hex.empty()) {
            iv_or_nonce = hex_to_bytes(opt.iv_hex);
        }

        if (uses_nonce(opt.mode) && !opt.nonce_hex.empty()) {
            iv_or_nonce = hex_to_bytes(opt.nonce_hex);
        }

        if (opt.command == "encrypt") {
            std::vector<unsigned char> plaintext;

            if (!opt.in_file.empty()) {
                plaintext = read_file(opt.in_file);
            } else if (!opt.text.empty()) {
                plaintext = text_to_bytes(opt.text);
            } else {
                throw std::runtime_error("Encrypt requires --text or --in.");
            }

            if (opt.mode == "ecb" && plaintext.size() > 16 * 1024) {
                throw std::runtime_error("ECB input larger than 16 KiB is blocked.");
            }

            Result r = encrypt_data(opt.mode, plaintext, key, iv_or_nonce, aad);

            if (!opt.out_file.empty()) {
                write_file(opt.out_file, r.data);
            }

            std::cout << "\n>> ENCRYPT RESULT <<\n";
            std::cout << "Mode       : " << opt.mode << "\n";
            std::cout << "Cipher hex : " << bytes_to_hex(r.data) << "\n";

            if (!r.iv_or_nonce.empty()) {
                if (uses_nonce(opt.mode)) {
                    std::cout << "Nonce hex  : " << bytes_to_hex(r.iv_or_nonce) << "\n";
                } else {
                    std::cout << "IV hex     : " << bytes_to_hex(r.iv_or_nonce) << "\n";
                }
            }

            if (!r.tag.empty()) {
                std::cout << "Tag hex    : " << bytes_to_hex(r.tag) << "\n";
            }

            if (!opt.out_file.empty()) {
                std::cout << "Output file: " << opt.out_file << "\n";
            }

            return 0;
        }

        if (opt.command == "decrypt") {
            std::vector<unsigned char> ciphertext;

            if (!opt.in_file.empty()) {
                ciphertext = read_file(opt.in_file);
            } else if (!opt.cipher_hex.empty()) {
                ciphertext = hex_to_bytes(opt.cipher_hex);
            } else {
                throw std::runtime_error("Decrypt requires --cipher-hex or --in.");
            }

            if (opt.mode != "ecb" && iv_or_nonce.empty()) {
                if (uses_nonce(opt.mode)) {
                    throw std::runtime_error("Decrypt requires --nonce for GCM/CCM.");
                } else {
                    throw std::runtime_error("Decrypt requires --iv.");
                }
            }

            std::vector<unsigned char> tag;

            if (is_aead(opt.mode)) {
                if (opt.tag_hex.empty()) {
                    throw std::runtime_error("AEAD decrypt requires --tag.");
                }
                tag = hex_to_bytes(opt.tag_hex);
            }

            Result r = decrypt_data(opt.mode, ciphertext, key, iv_or_nonce, aad, tag);

            if (!opt.out_file.empty()) {
                write_file(opt.out_file, r.data);
            }

            std::cout << "\n>> DECRYPT RESULT <<\n";
            std::cout << "Mode      : " << opt.mode << "\n";
            std::cout << "Plaintext : " << bytes_to_text(r.data) << "\n";

            if (!opt.out_file.empty()) {
                std::cout << "Output file: " << opt.out_file << "\n";
            }

            return 0;
        }

        return 1;

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ ERROR: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}