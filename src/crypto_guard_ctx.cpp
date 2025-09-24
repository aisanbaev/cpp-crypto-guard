#include "crypto_guard_ctx.h"
#include <array>
#include <memory>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>

namespace CryptoGuard {

class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); }
    ~Impl() { EVP_cleanup(); }

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        if (!inStream.good()) {
            throw std::runtime_error("Input stream failure");
        }
        if (!outStream.good()) {
            throw std::runtime_error("Output stream failure");
        }

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;

        auto ctxDeleter = [](EVP_CIPHER_CTX *ctx) {
            if (ctx)
                EVP_CIPHER_CTX_free(ctx);
        };
        std::unique_ptr<EVP_CIPHER_CTX, decltype(ctxDeleter)> ctx(EVP_CIPHER_CTX_new(), ctxDeleter);

        if (!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                               params.encrypt)) {
            throw std::runtime_error("Failed to initialize cipher");
        }

        constexpr size_t BUFFER_SIZE = 1024;
        std::vector<unsigned char> inBuf(BUFFER_SIZE);
        std::vector<unsigned char> outBuf(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
        int outLen;

        while (inStream.good()) {
            inStream.read(reinterpret_cast<char *>(inBuf.data()), BUFFER_SIZE);
            int inLen = static_cast<int>(inStream.gcount());

            if (inLen <= 0) {
                break;
            }

            if (!outStream.good()) {
                throw std::runtime_error("Output stream failure during encryption");
            }

            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), inLen)) {
                throw std::runtime_error("Failed to update cipher");
            }

            outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
            if (!outStream.good()) {
                throw std::runtime_error("Failed to write to output stream");
            }
        }

        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throw std::runtime_error("Failed to finalize cipher");
        }

        outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
        if (!outStream.good()) {
            throw std::runtime_error("Failed to write final data to output stream");
        }
    }

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}

    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }

private:
    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;             // AES-256 key size
        static const size_t IV_SIZE = 16;              // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };

    AesCipherParams CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;

// API методы
void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) { return pImpl_->CalculateChecksum(inStream); }

}  // namespace CryptoGuard