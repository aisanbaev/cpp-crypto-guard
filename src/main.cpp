#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <filesystem>
#include <fstream>
#include <print>
#include <stdexcept>

namespace {

std::fstream openInputFile(const std::string &filename) {
    std::fstream file(filename, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open input file: " + filename);
    }
    return file;
}

std::fstream openOutputFile(const std::string &filename) {
    std::fstream file(filename, std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot create output file: " + filename);
    }
    return file;
}

class AutoDeleteFile {
public:
    AutoDeleteFile(const std::string &filename) : filename_(filename), shouldDelete_(true) {}

    ~AutoDeleteFile() {
        if (shouldDelete_) {
            std::filesystem::remove(filename_);
        }
    }

    void commit() { shouldDelete_ = false; }

private:
    std::string filename_;
    bool shouldDelete_;
};

}  // unnamed namespace

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {

        case COMMAND_TYPE::ENCRYPT: {
            auto inputFile = openInputFile(options.GetInputFile());
            auto outputFile = openOutputFile(options.GetOutputFile());

            AutoDeleteFile autoDelete(options.GetOutputFile());
            cryptoCtx.EncryptFile(inputFile, outputFile, options.GetPassword());
            autoDelete.commit();

            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            auto inputFile = openInputFile(options.GetInputFile());
            auto outputFile = openOutputFile(options.GetOutputFile());

            AutoDeleteFile autoDelete(options.GetOutputFile());
            cryptoCtx.DecryptFile(inputFile, outputFile, options.GetPassword());
            autoDelete.commit();

            std::print("File decoded successfully\n");
            break;
        }

        case COMMAND_TYPE::CHECKSUM: {
            auto inputFile = openInputFile(options.GetInputFile());
            std::string checksum = cryptoCtx.CalculateChecksum(inputFile);
            std::print("Checksum: {}\n", checksum);
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}