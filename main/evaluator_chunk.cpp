#include "RSAUtils.h"
#include <iostream>
#include <string>
#include <botan/rsa.h>
#include <filesystem>

namespace fs = std::filesystem;


int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " --alg [RSA] --keysize <key size> <input directory> <output directory>\n";
        return 1;
    }

    std::string algorithm(argv[2]);
    size_t keySize = std::stoi(argv[4]);
    std::string inputDir(argv[5]);
    std::string outputDir(argv[6]);

    try {
        if (algorithm == "RSA") {
            encryptDirectoryRSA(inputDir, outputDir, keySize);
        } else {
            std::cerr << "Unsupported algorithm. Currently supported: RSA\n";
            return 1;
        }
    } catch (const Botan::Exception& e) {
        std::cerr << "Encryption failed: " << e.what() << '\n';
        return 1;
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Filesystem error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}
