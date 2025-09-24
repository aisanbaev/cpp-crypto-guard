#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {

        case COMMAND_TYPE::ENCRYPT: {
            std::fstream inputFile(options.GetInputFile(), std::ios::in);
            if (!inputFile.is_open()) {
                throw std::runtime_error("Cannot open input file: " + options.GetInputFile());
            }

            std::fstream outputFile(options.GetOutputFile(), std::ios::out | std::ios::binary);
            if (!outputFile.is_open()) {
                throw std::runtime_error("Cannot create output file: " + options.GetOutputFile());
            }

            cryptoCtx.EncryptFile(inputFile, outputFile, options.GetPassword());
            std::print("File encoded successfully\n");
            break;
        }

        case COMMAND_TYPE::DECRYPT:
            std::print("File decoded successfully\n");
            break;

        case COMMAND_TYPE::CHECKSUM:
            std::print("Checksum: {}\n", "CHECKSUM_NOT_IMPLEMENTED");
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}