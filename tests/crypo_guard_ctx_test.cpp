#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <sstream>
#include <string>

namespace CryptoGuard {

TEST(CryptoGuardEncrypt, ValidData) {
    CryptoGuardCtx ctx;

    std::string original_data = "Hello OpenSSL crypto world!";
    std::stringstream input_stream(original_data);
    std::stringstream output_stream;

    EXPECT_NO_THROW(ctx.EncryptFile(input_stream, output_stream, "password123"));

    std::string encrypted_data = output_stream.str();
    EXPECT_FALSE(encrypted_data.empty());
    EXPECT_NE(encrypted_data, original_data);
}

TEST(CryptoGuardEncrypt, EmptyData) {
    CryptoGuardCtx ctx;

    std::string original_data = "";
    std::stringstream input_stream(original_data);
    std::stringstream output_stream;

    EXPECT_NO_THROW(ctx.EncryptFile(input_stream, output_stream, "password123"));
    EXPECT_FALSE(output_stream.str().empty());
}

TEST(CryptoGuardEncrypt, InvalidInputStream) {
    CryptoGuardCtx ctx;

    std::stringstream input_stream("test data");
    std::stringstream output_stream;
    input_stream.setstate(std::ios::failbit);

    ASSERT_THROW(ctx.EncryptFile(input_stream, output_stream, "password123"), std::runtime_error);
}

TEST(CryptoGuardEncrypt, InvalidOutputStream) {
    CryptoGuardCtx ctx;

    std::stringstream input_stream("test data");
    std::stringstream output_stream;
    output_stream.setstate(std::ios::failbit);

    ASSERT_THROW(ctx.EncryptFile(input_stream, output_stream, "password123"), std::runtime_error);
}

TEST(CryptoGuardEncrypt, DifferentPasswords) {
    CryptoGuardCtx ctx;

    std::string original_data = "Test data for encryption comparison";
    std::stringstream input_stream1(original_data);
    std::stringstream input_stream2(original_data);
    std::stringstream input_stream3(original_data);
    std::stringstream output_stream1, output_stream2, output_stream3;

    ctx.EncryptFile(input_stream1, output_stream1, "password1");
    ctx.EncryptFile(input_stream2, output_stream2, "password2");
    EXPECT_NE(output_stream1.str(), output_stream2.str());

    ctx.EncryptFile(input_stream3, output_stream3, "password1");
    EXPECT_EQ(output_stream1.str(), output_stream3.str());
}

TEST(CryptoGuardEncrypt, VeryLongString) {
    CryptoGuardCtx ctx;

    std::string long_data(10000, 'A');
    for (size_t i = 0; i < long_data.length(); ++i) {
        long_data[i] = static_cast<char>('A' + (i % 26));
    }

    std::stringstream input_stream(long_data);
    std::stringstream output_stream;
    EXPECT_NO_THROW(ctx.EncryptFile(input_stream, output_stream, "verylongstringpassword"));

    std::string encrypted_data = output_stream.str();

    EXPECT_FALSE(encrypted_data.empty());
    EXPECT_NE(encrypted_data, long_data);
    EXPECT_GE(encrypted_data.length(), long_data.length());
}

TEST(CryptoGuardDecrypt, ValidData) {
    CryptoGuardCtx ctx;

    std::string original_data = "Hello OpenSSL crypto world!";
    std::stringstream input_stream(original_data);
    std::stringstream encrypted_stream;
    std::stringstream decrypted_stream;

    ctx.EncryptFile(input_stream, encrypted_stream, "password123");
    std::string encrypted_data = encrypted_stream.str();

    std::stringstream decrypt_input(encrypted_data);
    EXPECT_NO_THROW(ctx.DecryptFile(decrypt_input, decrypted_stream, "password123"));

    std::string decrypted_data = decrypted_stream.str();
    EXPECT_EQ(decrypted_data, original_data);
}

TEST(CryptoGuardDecrypt, EmptyData) {
    CryptoGuardCtx ctx;

    std::string original_data = "";
    std::stringstream input_stream(original_data);
    std::stringstream encrypted_stream;
    std::stringstream decrypted_stream;

    ctx.EncryptFile(input_stream, encrypted_stream, "password123");
    std::string encrypted_data = encrypted_stream.str();

    std::stringstream decrypt_input(encrypted_data);
    EXPECT_NO_THROW(ctx.DecryptFile(decrypt_input, decrypted_stream, "password123"));

    std::string decrypted_data = decrypted_stream.str();
    EXPECT_EQ(decrypted_data, original_data);
}

TEST(CryptoGuardDecrypt, InvalidInputStream) {
    CryptoGuardCtx ctx;

    std::stringstream encrypted_stream("test data");
    std::stringstream decrypted_stream;
    encrypted_stream.setstate(std::ios::failbit);

    ASSERT_THROW(ctx.DecryptFile(encrypted_stream, decrypted_stream, "password123"), std::runtime_error);
}

TEST(CryptoGuardDecrypt, InvalidOutputStream) {
    CryptoGuardCtx ctx;

    std::stringstream encrypted_stream("test data");
    std::stringstream decrypted_stream;
    decrypted_stream.setstate(std::ios::failbit);

    ASSERT_THROW(ctx.DecryptFile(encrypted_stream, decrypted_stream, "password123"), std::runtime_error);
}

TEST(CryptoGuardDecrypt, WrongPassword) {
    CryptoGuardCtx ctx;

    std::string original_data = "Hello OpenSSL crypto world!";
    std::stringstream input_stream(original_data);
    std::stringstream encrypted_stream;
    std::stringstream decrypted_stream;

    ctx.EncryptFile(input_stream, encrypted_stream, "password123");
    std::string encrypted_data = encrypted_stream.str();

    std::stringstream decrypt_input(encrypted_data);
    EXPECT_THROW(
        {
            try {
                ctx.DecryptFile(decrypt_input, decrypted_stream, "wrong_password");
            } catch (const std::runtime_error &e) {
                EXPECT_EQ(std::string(e.what()), "Failed to finalize cipher");
                throw;
            }
        },
        std::runtime_error);
}

TEST(CryptoGuardDecrypt, VeryLongString) {
    CryptoGuardCtx ctx;

    std::string original_data(10000, 'A');
    for (size_t i = 0; i < original_data.length(); ++i) {
        original_data[i] = static_cast<char>('A' + (i % 26));
    }

    std::stringstream input_stream(original_data);
    std::stringstream encrypted_stream;
    std::stringstream decrypted_stream;

    EXPECT_NO_THROW(ctx.EncryptFile(input_stream, encrypted_stream, "verylongstringpassword"));
    std::string encrypted_data = encrypted_stream.str();

    std::stringstream decrypt_input(encrypted_data);
    EXPECT_NO_THROW(ctx.DecryptFile(decrypt_input, decrypted_stream, "verylongstringpassword"));

    std::string decrypted_data = decrypted_stream.str();
    EXPECT_EQ(decrypted_data, original_data);
}

TEST(CryptoGuardCalculateChecksum, ValidData) {
    CryptoGuardCtx ctx;

    std::string data = "Hello World";
    std::stringstream input_stream(data);

    std::string checksum = ctx.CalculateChecksum(input_stream);

    // SHA-256 хеш для "Hello World"
    EXPECT_EQ(checksum, "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e");
}

TEST(CryptoGuardCalculateChecksum, EmptyData) {
    CryptoGuardCtx ctx;

    std::string data = "";
    std::stringstream input_stream(data);

    std::string checksum = ctx.CalculateChecksum(input_stream);

    // SHA-256 хеш для пустой строки
    EXPECT_EQ(checksum, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(CryptoGuardCalculateChecksum, InvalidInputStream) {
    CryptoGuardCtx ctx;

    std::stringstream input_stream("test data");
    input_stream.setstate(std::ios::failbit);

    ASSERT_THROW(ctx.CalculateChecksum(input_stream), std::runtime_error);
}

TEST(CryptoGuardCalculateChecksum, DifferentDataChecksum) {
    CryptoGuardCtx ctx;

    std::string data1 = "Hello World";
    std::string data2 = "Hello World!";

    std::stringstream input_stream1(data1);
    std::stringstream input_stream2(data2);

    std::string checksum1 = ctx.CalculateChecksum(input_stream1);
    std::string checksum2 = ctx.CalculateChecksum(input_stream2);

    EXPECT_NE(checksum1, checksum2);
}

TEST(CryptoGuardCalculateChecksum, SameDataSameChecksum) {
    CryptoGuardCtx ctx;

    std::string data = "Test data for checksum verification";

    std::stringstream input_stream1(data);
    std::stringstream input_stream2(data);

    std::string checksum1 = ctx.CalculateChecksum(input_stream1);
    std::string checksum2 = ctx.CalculateChecksum(input_stream2);

    EXPECT_EQ(checksum1, checksum2);
}

TEST(CryptoGuardCalculateChecksum, VeryLongString) {
    CryptoGuardCtx ctx;

    std::string long_data(10000, 'A');
    for (size_t i = 0; i < long_data.length(); ++i) {
        long_data[i] = static_cast<char>('A' + (i % 26));
    }

    std::stringstream input_stream(long_data);
    std::string checksum = ctx.CalculateChecksum(input_stream);

    EXPECT_FALSE(checksum.empty());
    EXPECT_EQ(checksum.length(), 64);
}

TEST(CryptoGuardCalculateChecksum, ChecksumBeforeAfterEncryption) {
    CryptoGuardCtx ctx;

    std::string original_data = "Hello OpenSSL crypto world!";
    std::stringstream original_stream(original_data);

    // Подсчитываем контрольную сумму
    std::string original_checksum = ctx.CalculateChecksum(original_stream);

    // Зашифровываем данные
    std::stringstream input_stream(original_data);
    std::stringstream encrypted_stream;
    ctx.EncryptFile(input_stream, encrypted_stream, "password123");
    std::string encrypted_data = encrypted_stream.str();

    // Подсчитываем контрольную сумму зашифрованных данных
    std::stringstream encrypted_for_checksum(encrypted_data);
    std::string encrypted_checksum = ctx.CalculateChecksum(encrypted_for_checksum);

    // Зашифрованные данные должны иметь другую контрольную сумму
    EXPECT_NE(original_checksum, encrypted_checksum);

    // Расшифровываем данные
    std::stringstream decrypt_input(encrypted_data);
    std::stringstream decrypted_stream;
    ctx.DecryptFile(decrypt_input, decrypted_stream, "password123");
    std::string decrypted_data = decrypted_stream.str();

    // Подсчитываем контрольную сумму расшифрованных данных
    std::stringstream decrypted_for_checksum(decrypted_data);
    std::string decrypted_checksum = ctx.CalculateChecksum(decrypted_for_checksum);

    // Контрольная сумма расшифрованных данных должна совпадать с оригинальной
    EXPECT_EQ(original_checksum, decrypted_checksum);
    EXPECT_EQ(decrypted_data, original_data);
}

TEST(CryptoGuardDataIntegrity, DecryptFailsWithTruncatedData) {
    CryptoGuardCtx ctx;

    std::string original_data = "Test data that will be encrypted and then corrupted";
    std::stringstream input_stream(original_data);
    std::stringstream encrypted_stream;
    std::stringstream decrypted_stream;

    // Зашифровываем данные
    ctx.EncryptFile(input_stream, encrypted_stream, "test_password");
    std::string encrypted_data = encrypted_stream.str();

    EXPECT_FALSE(encrypted_data.empty());

    // Обрезаем часть зашифрованных данных
    std::string truncated_encrypted_data = encrypted_data.substr(0, encrypted_data.length() - 10);

    // Пытаемся расшифровать обрезанные данные
    std::stringstream truncated_input(truncated_encrypted_data);
    ASSERT_THROW(ctx.DecryptFile(truncated_input, decrypted_stream, "test_password"), std::runtime_error);
}

}  // namespace CryptoGuard
