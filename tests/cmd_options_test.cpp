#include "cmd_options.h"
#include <gtest/gtest.h>
#include <stdexcept>

namespace CryptoGuard {

TEST(ProgramOptions, EncryptCommandWithAllParameters) {
    ProgramOptions options;
    const char *argv[] = {"program", "--command",  "encrypt", "-i",         "input.txt",
                          "-o",      "output.txt", "-p",      "password123"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    ASSERT_NO_THROW(options.Parse(argc, const_cast<char **>(argv)));

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "password123");
}

TEST(ProgramOptions, DecryptCommandWithAllParameters) {
    ProgramOptions options;
    const char *argv[] = {"program", "--command",     "decrypt", "-i",        "encrypted.txt",
                          "-o",      "decrypted.txt", "-p",      "mypassword"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    ASSERT_NO_THROW(options.Parse(argc, const_cast<char **>(argv)));

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(options.GetInputFile(), "encrypted.txt");
    EXPECT_EQ(options.GetOutputFile(), "decrypted.txt");
    EXPECT_EQ(options.GetPassword(), "mypassword");
}

TEST(ProgramOptions, ChecksumCommandWithInputFile) {
    ProgramOptions options;
    const char *argv[] = {"program", "--command", "checksum", "-i", "file.txt"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    ASSERT_NO_THROW(options.Parse(argc, const_cast<char **>(argv)));

    EXPECT_EQ(options.GetCommand(), ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(options.GetInputFile(), "file.txt");
    EXPECT_EQ(options.GetOutputFile(), "");
    EXPECT_EQ(options.GetPassword(), "");
}

TEST(ProgramOptions, HelpOption) {
    ProgramOptions options;
    const char *argv[] = {"program", "--help"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_EXIT(options.Parse(argc, const_cast<char **>(argv)), ::testing::ExitedWithCode(0), ".*");
}

TEST(ProgramOptions, MissingRequiredCommand) {
    ProgramOptions options;
    const char *argv[] = {"program", "-i", "input.txt", "-o", "output.txt", "-p", "password"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_THROW(options.Parse(argc, const_cast<char **>(argv)), std::invalid_argument);
}

TEST(ProgramOptions, InvalidCommand) {
    ProgramOptions options;
    const char *argv[] = {"program", "--command", "invalid_cmd", "-i", "input.txt"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_THROW(options.Parse(argc, const_cast<char **>(argv)), std::invalid_argument);
}

TEST(ProgramOptions, EncryptMissingRequiredParameters) {
    ProgramOptions options;
    const char *argv[] = {"program", "--command", "encrypt", "-i", "input.txt"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_THROW(options.Parse(argc, const_cast<char **>(argv)), std::invalid_argument);
}

TEST(ProgramOptions, ChecksumWithoutInputFile) {
    ProgramOptions options;
    const char *argv[] = {"program", "--command", "checksum"};
    int argc = sizeof(argv) / sizeof(argv[0]);

    EXPECT_THROW(options.Parse(argc, const_cast<char **>(argv)), std::invalid_argument);
}

}  // namespace CryptoGuard