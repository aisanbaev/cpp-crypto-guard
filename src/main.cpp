#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <filesystem>
#include <fstream>
#include <print>
#include <stdexcept>

namespace {

class FileOpener {
public:
    static std::fstream openInput(const std::string &filename) {
        return openFile(filename, std::ios::in | std::ios::binary, "open input file");
    }

    static std::fstream openOutput(const std::string &filename) {
        return openFile(filename, std::ios::out | std::ios::binary, "create output file");
    }

private:
    static std::fstream openFile(const std::string &filename, std::ios::openmode mode, const std::string &action) {
        std::fstream file(filename, mode);
        if (!file.is_open()) {
            throw std::runtime_error("Cannot " + action + ": " + filename);
        }
        return file;
    }
};

class TemporaryFile {
public:
    TemporaryFile(const std::string &filename) : filename_(filename), shouldDelete_(true) {}

    ~TemporaryFile() {
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
            auto inputFile = FileOpener::openInput(options.GetInputFile());
            auto outputFile = FileOpener::openOutput(options.GetOutputFile());

            TemporaryFile tempOutput(options.GetOutputFile());
            cryptoCtx.EncryptFile(inputFile, outputFile, options.GetPassword());
            tempOutput.commit();

            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            auto inputFile = FileOpener::openInput(options.GetInputFile());
            auto outputFile = FileOpener::openOutput(options.GetOutputFile());

            TemporaryFile tempOutput(options.GetOutputFile());
            cryptoCtx.DecryptFile(inputFile, outputFile, options.GetPassword());
            tempOutput.commit();

            std::print("File decoded successfully\n");
            break;
        }

        case COMMAND_TYPE::CHECKSUM: {
            auto inputFile = FileOpener::openInput(options.GetInputFile());
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