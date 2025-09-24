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

}  // namespace CryptoGuard
