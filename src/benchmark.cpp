#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/xts.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>
#include <cryptopp/secblock.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

using byte_t = CryptoPP::byte;

struct BenchSize {
    std::string label;
    size_t bytes;
    int repeats_quick;
    int repeats_full;
};

struct Stats {
    double mean_ms;
    double median_ms;
    double stddev_ms;
    double ci95_ms;
};

static std::string get_arg(int argc, char* argv[], const std::string& name) {
    for (int i = 0; i < argc - 1; ++i) {
        if (std::string(argv[i]) == name) {
            return argv[i + 1];
        }
    }
    return "";
}

static void random_bytes(std::vector<byte_t>& data) {
    CryptoPP::AutoSeededRandomPool prng;
    prng.GenerateBlock(data.data(), data.size());
}

template <typename Func>
static double measure_ms(Func fn, int repeats) {
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < repeats; ++i) {
        fn();
    }

    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;
    return elapsed.count() / repeats;
}

static Stats compute_stats(std::vector<double> values) {
    Stats s{};

    double sum = std::accumulate(values.begin(), values.end(), 0.0);
    s.mean_ms = sum / values.size();

    std::sort(values.begin(), values.end());

    if (values.size() % 2 == 0) {
        s.median_ms = (values[values.size() / 2 - 1] + values[values.size() / 2]) / 2.0;
    } else {
        s.median_ms = values[values.size() / 2];
    }

    double variance = 0.0;

    for (double v : values) {
        double diff = v - s.mean_ms;
        variance += diff * diff;
    }

    if (values.size() > 1) {
        variance /= static_cast<double>(values.size() - 1);
    }

    s.stddev_ms = std::sqrt(variance);
    s.ci95_ms = 1.96 * s.stddev_ms / std::sqrt(static_cast<double>(values.size()));

    return s;
}

static double throughput_mib_s(size_t bytes, double mean_ms) {
    double mib = static_cast<double>(bytes) / (1024.0 * 1024.0);
    double sec = mean_ms / 1000.0;

    if (sec <= 0.0) {
        return 0.0;
    }

    return mib / sec;
}

static void write_row(
    std::ofstream& csv,
    const std::string& mode,
    const std::string& size_label,
    size_t bytes,
    const std::string& operation,
    int runs,
    int repeats,
    const Stats& st
) {
    csv << mode << ","
        << size_label << ","
        << bytes << ","
        << operation << ","
        << runs << ","
        << repeats << ","
        << std::fixed << std::setprecision(6) << st.mean_ms << ","
        << std::fixed << std::setprecision(6) << st.median_ms << ","
        << std::fixed << std::setprecision(6) << st.stddev_ms << ","
        << std::fixed << std::setprecision(6) << st.ci95_ms << ","
        << std::fixed << std::setprecision(2) << throughput_mib_s(bytes, st.mean_ms)
        << "\n";

    std::cout << "[OK] "
              << std::setw(4) << mode << " "
              << std::setw(6) << size_label << " "
              << std::setw(7) << operation
              << " mean=" << std::fixed << std::setprecision(4) << st.mean_ms << " ms"
              << " speed=" << std::fixed << std::setprecision(2) << throughput_mib_s(bytes, st.mean_ms)
              << " MiB/s\n";
}

template <typename EncMode, typename DecMode>
static void bench_mode_with_iv(
    std::ofstream& csv,
    const std::string& mode,
    const BenchSize& size,
    int runs,
    int repeats
) {
    std::vector<byte_t> key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    std::vector<byte_t> iv(CryptoPP::AES::BLOCKSIZE);
    std::vector<byte_t> plaintext(size.bytes);
    std::vector<byte_t> ciphertext(size.bytes);
    std::vector<byte_t> recovered(size.bytes);

    random_bytes(key);
    random_bytes(iv);
    random_bytes(plaintext);

    EncMode enc;
    DecMode dec;

    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    enc.ProcessData(ciphertext.data(), plaintext.data(), plaintext.size());

    std::vector<double> enc_times;
    std::vector<double> dec_times;

    for (int i = 0; i < runs; ++i) {
        enc_times.push_back(measure_ms([&]() {
            enc.ProcessData(ciphertext.data(), plaintext.data(), plaintext.size());
        }, repeats));

        dec_times.push_back(measure_ms([&]() {
            dec.ProcessData(recovered.data(), ciphertext.data(), ciphertext.size());
        }, repeats));
    }

    write_row(csv, mode, size.label, size.bytes, "encrypt", runs, repeats, compute_stats(enc_times));
    write_row(csv, mode, size.label, size.bytes, "decrypt", runs, repeats, compute_stats(dec_times));
}

static void bench_ecb(
    std::ofstream& csv,
    const BenchSize& size,
    int runs,
    int repeats
) {
    std::vector<byte_t> key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    std::vector<byte_t> plaintext(size.bytes);
    std::vector<byte_t> ciphertext(size.bytes);
    std::vector<byte_t> recovered(size.bytes);

    random_bytes(key);
    random_bytes(plaintext);

    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc;
    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec;

    enc.SetKey(key.data(), key.size());
    dec.SetKey(key.data(), key.size());

    enc.ProcessData(ciphertext.data(), plaintext.data(), plaintext.size());

    std::vector<double> enc_times;
    std::vector<double> dec_times;

    for (int i = 0; i < runs; ++i) {
        enc_times.push_back(measure_ms([&]() {
            enc.ProcessData(ciphertext.data(), plaintext.data(), plaintext.size());
        }, repeats));

        dec_times.push_back(measure_ms([&]() {
            dec.ProcessData(recovered.data(), ciphertext.data(), ciphertext.size());
        }, repeats));
    }

    write_row(csv, "ecb", size.label, size.bytes, "encrypt", runs, repeats, compute_stats(enc_times));
    write_row(csv, "ecb", size.label, size.bytes, "decrypt", runs, repeats, compute_stats(dec_times));
}

static void bench_xts(
    std::ofstream& csv,
    const BenchSize& size,
    int runs,
    int repeats
) {
    std::vector<byte_t> key(32);
    std::vector<byte_t> iv(CryptoPP::AES::BLOCKSIZE);
    std::vector<byte_t> plaintext(size.bytes);
    std::vector<byte_t> ciphertext(size.bytes);
    std::vector<byte_t> recovered(size.bytes);

    random_bytes(key);
    random_bytes(iv);
    random_bytes(plaintext);

    CryptoPP::XTS_Mode<CryptoPP::AES>::Encryption enc;
    CryptoPP::XTS_Mode<CryptoPP::AES>::Decryption dec;

    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
    dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    enc.ProcessData(ciphertext.data(), plaintext.data(), plaintext.size());

    std::vector<double> enc_times;
    std::vector<double> dec_times;

    for (int i = 0; i < runs; ++i) {
        enc_times.push_back(measure_ms([&]() {
            enc.ProcessData(ciphertext.data(), plaintext.data(), plaintext.size());
        }, repeats));

        dec_times.push_back(measure_ms([&]() {
            dec.ProcessData(recovered.data(), ciphertext.data(), ciphertext.size());
        }, repeats));
    }

    write_row(csv, "xts", size.label, size.bytes, "encrypt", runs, repeats, compute_stats(enc_times));
    write_row(csv, "xts", size.label, size.bytes, "decrypt", runs, repeats, compute_stats(dec_times));
}

static void bench_gcm(
    std::ofstream& csv,
    const BenchSize& size,
    int runs,
    int repeats
) {
    const size_t TAG_SIZE = 16;

    std::vector<byte_t> key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    std::vector<byte_t> iv(12);
    std::vector<byte_t> aad = {'l', 'a', 'b', '1'};
    std::string plaintext(size.bytes, '\0');

    std::vector<byte_t> plain_bytes(size.bytes);
    random_bytes(key);
    random_bytes(iv);
    random_bytes(plain_bytes);

    plaintext.assign(reinterpret_cast<const char*>(plain_bytes.data()), plain_bytes.size());

    std::string ciphertext;
    std::string recovered;

    auto encrypt_once = [&]() {
        ciphertext.clear();

        CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::AuthenticatedEncryptionFilter ef(
            enc,
            new CryptoPP::StringSink(ciphertext),
            false,
            TAG_SIZE
        );

        ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
        ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, reinterpret_cast<const byte_t*>(plaintext.data()), plaintext.size());
        ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    };

    encrypt_once();

    auto decrypt_once = [&]() {
        recovered.clear();

        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::AuthenticatedDecryptionFilter df(
            dec,
            new CryptoPP::StringSink(recovered),
            CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            TAG_SIZE
        );

        df.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
        df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, reinterpret_cast<const byte_t*>(ciphertext.data()), ciphertext.size());
        df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    };

    std::vector<double> enc_times;
    std::vector<double> dec_times;

    for (int i = 0; i < runs; ++i) {
        enc_times.push_back(measure_ms(encrypt_once, repeats));
        dec_times.push_back(measure_ms(decrypt_once, repeats));
    }

    write_row(csv, "gcm", size.label, size.bytes, "encrypt", runs, repeats, compute_stats(enc_times));
    write_row(csv, "gcm", size.label, size.bytes, "decrypt", runs, repeats, compute_stats(dec_times));
}

static void bench_ccm(
    std::ofstream& csv,
    const BenchSize& size,
    int runs,
    int repeats
) {
    const size_t TAG_SIZE = 16;

    std::vector<byte_t> key(CryptoPP::AES::DEFAULT_KEYLENGTH);
    std::vector<byte_t> nonce(12);
    std::vector<byte_t> aad = {'l', 'a', 'b', '1'};
    std::vector<byte_t> plain_bytes(size.bytes);

    random_bytes(key);
    random_bytes(nonce);
    random_bytes(plain_bytes);

    std::string plaintext(reinterpret_cast<const char*>(plain_bytes.data()), plain_bytes.size());
    std::string ciphertext;
    std::string recovered;

    auto encrypt_once = [&]() {
        ciphertext.clear();

        CryptoPP::CCM<CryptoPP::AES, TAG_SIZE>::Encryption enc;
        enc.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());
        enc.SpecifyDataLengths(aad.size(), plaintext.size(), 0);

        CryptoPP::AuthenticatedEncryptionFilter ef(
            enc,
            new CryptoPP::StringSink(ciphertext),
            false,
            TAG_SIZE
        );

        ef.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
        ef.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        ef.ChannelPut(CryptoPP::DEFAULT_CHANNEL, reinterpret_cast<const byte_t*>(plaintext.data()), plaintext.size());
        ef.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    };

    encrypt_once();

    auto decrypt_once = [&]() {
        recovered.clear();

        CryptoPP::CCM<CryptoPP::AES, TAG_SIZE>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), nonce.data(), nonce.size());
        dec.SpecifyDataLengths(aad.size(), ciphertext.size() - TAG_SIZE, 0);

        CryptoPP::AuthenticatedDecryptionFilter df(
            dec,
            new CryptoPP::StringSink(recovered),
            CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
            TAG_SIZE
        );

        df.ChannelPut(CryptoPP::AAD_CHANNEL, aad.data(), aad.size());
        df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, reinterpret_cast<const byte_t*>(ciphertext.data()), ciphertext.size());
        df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
    };

    std::vector<double> enc_times;
    std::vector<double> dec_times;

    for (int i = 0; i < runs; ++i) {
        enc_times.push_back(measure_ms(encrypt_once, repeats));
        dec_times.push_back(measure_ms(decrypt_once, repeats));
    }

    write_row(csv, "ccm", size.label, size.bytes, "encrypt", runs, repeats, compute_stats(enc_times));
    write_row(csv, "ccm", size.label, size.bytes, "decrypt", runs, repeats, compute_stats(dec_times));
}

int main(int argc, char* argv[]) {
    std::string profile = get_arg(argc, argv, "--profile");
    std::string out = get_arg(argc, argv, "--out");

    if (profile.empty()) {
        profile = "quick";
    }

    if (out.empty()) {
        out = "results/lab1_aes_benchmark_" + profile + ".csv";
    }

    int runs = 5;

    if (profile == "full") {
        runs = 30;
    } else if (profile == "quick") {
        runs = 5;
    } else {
        std::cerr << "[ERROR] Unknown profile. Use --profile quick or --profile full.\n";
        return 1;
    }

    std::vector<BenchSize> sizes = {
        {"1KB",   1 * 1024,        500, 1000},
        {"4KB",   4 * 1024,        300, 700},
        {"16KB",  16 * 1024,       150, 300},
        {"256KB", 256 * 1024,      30,  80},
        {"1MB",   1 * 1024 * 1024, 10,  30},
        {"8MB",   8 * 1024 * 1024, 2,   8}
    };

    std::ofstream csv(out);

    if (!csv) {
        std::cerr << "[ERROR] Cannot open CSV output: " << out << "\n";
        return 1;
    }

    csv << "mode,size_label,bytes,operation,runs,repeats,mean_ms,median_ms,stddev_ms,ci95_ms,throughput_mib_s\n";

    std::cout << ">> LAB 1 AES BENCHMARK\n";
    std::cout << "Profile : " << profile << "\n";
    std::cout << "Runs    : " << runs << "\n";
    std::cout << "Output  : " << out << "\n\n";

    try {
        for (const auto& s : sizes) {
            int repeats = (profile == "full") ? s.repeats_full : s.repeats_quick;

            bench_ecb(csv, s, runs, repeats);

            bench_mode_with_iv<
                CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption,
                CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption
            >(csv, "cbc", s, runs, repeats);

            bench_mode_with_iv<
                CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption,
                CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption
            >(csv, "cfb", s, runs, repeats);

            bench_mode_with_iv<
                CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption,
                CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption
            >(csv, "ofb", s, runs, repeats);

            bench_mode_with_iv<
                CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption,
                CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption
            >(csv, "ctr", s, runs, repeats);

            bench_xts(csv, s, runs, repeats);
            bench_gcm(csv, s, runs, repeats);
            bench_ccm(csv, s, runs, repeats);

            std::cout << "\n";
        }
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "[CRYPTOPP ERROR] " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }

    std::cout << ">> BENCHMARK DONE\n";
    std::cout << "CSV output: " << out << "\n";

    return 0;
}
