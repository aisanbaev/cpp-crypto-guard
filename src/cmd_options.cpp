#include "cmd_options.h"
#include <boost/program_options.hpp>
#include <iostream>
#include <stdexcept>

namespace po = boost::program_options;

namespace CryptoGuard {

// clang-format off
ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()
        ("help,h", "produce help message")
        ("command", po::value<std::string>(), "command: encrypt, decrypt or checksum")
        ("input,i", po::value<std::string>(), "input file path")
        ("output,o", po::value<std::string>(), "output file path")
        ("password,p", po::value<std::string>(), "password for encryption/decryption");
}
// clang-format on

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc_ << std::endl;
        exit(0);
    }

    if (!vm.count("command")) {
        throw std::invalid_argument("Command is required");
    }

    std::string commandStr = vm["command"].as<std::string>();
    auto it = commandMapping_.find(commandStr);
    if (it != commandMapping_.end()) {
        command_ = it->second;
    } else {
        throw std::invalid_argument("Invalid command: " + commandStr);
    }

    // Для encrypt и decrypt требуются input, output и password
    if (command_ == COMMAND_TYPE::ENCRYPT || command_ == COMMAND_TYPE::DECRYPT) {
        if (!vm.count("input") || !vm.count("output") || !vm.count("password")) {
            throw std::invalid_argument("For encrypt/decrypt commands input, output and password are required");
        }
        inputFile_ = vm["input"].as<std::string>();
        outputFile_ = vm["output"].as<std::string>();
        password_ = vm["password"].as<std::string>();
    }
    // Для checksum требуется только input
    else if (command_ == COMMAND_TYPE::CHECKSUM) {
        if (!vm.count("input")) {
            throw std::invalid_argument("Input file is required for checksum command");
        }
        inputFile_ = vm["input"].as<std::string>();
    }
}

}  // namespace CryptoGuard
