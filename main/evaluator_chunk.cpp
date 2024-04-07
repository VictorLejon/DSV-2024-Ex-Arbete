#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/x509_key.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <chrono>

namespace fs = std::filesystem;

void encryptChunkRSA(const Botan::PK_Encryptor_EME& encryptor, std::vector<uint8_t>& buffer, std::ofstream& outFile, unsigned long long& chunkCount) {
    Botan::AutoSeeded_RNG rng;
    std::vector<uint8_t> ciphertext = encryptor.encrypt(buffer.data(), buffer.size(), rng);
    outFile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    chunkCount++; // Increment the chunk counter
}

void encryptFileRSA(const std::string& inputFilename, const std::string& outputFilename, size_t keySize) {
    auto start = std::chrono::high_resolution_clock::now();
    unsigned long long chunkCount = 0; // Initialize chunk counter
    
    Botan::AutoSeeded_RNG rng;
    Botan::RSA_PrivateKey privateKey(rng, keySize);
    Botan::PK_Encryptor_EME encryptor(privateKey, rng, "EME1(SHA-256)");

    std::ifstream inFile(inputFilename, std::ios::binary);
    std::ofstream outFile(outputFilename, std::ios::binary);

    size_t maxChunkSize = keySize == 1024 ? 117 : 190; // Adjust based on key size and padding scheme

    std::vector<uint8_t> buffer(maxChunkSize);
    while (inFile.read(reinterpret_cast<char*>(buffer.data()), maxChunkSize) || inFile.gcount() > 0) {
        size_t bytesRead = inFile.gcount();
        buffer.resize(bytesRead); // Adjust buffer size for the last read chunk
        encryptChunkRSA(encryptor, buffer, outFile, chunkCount);
        buffer.resize(maxChunkSize); // Reset buffer size for the next chunk
    }

    auto end = std::chrono::high_resolution_clock::now();

    inFile.close();
    outFile.close();

    std::chrono::duration<double, std::milli> encryptionTime = end - start;
    
    // Calculate file sizes
    auto inputFileSize = fs::file_size(inputFilename);
    auto outputFileSize = fs::file_size(outputFilename);
    
    std::cout << "File: " << inputFilename << " encrypted in " << encryptionTime.count() << " milliseconds with " << chunkCount << " chunks." << std::endl;
    std::cout << "Input file size: " << inputFileSize << " bytes, Output file size: " << outputFileSize << " bytes.\n" << std::endl;
}

void encryptDirectoryRSA(const std::string& inputDir, const std::string& outputDir, size_t keySize) {
    
    fs::create_directories(outputDir);

    for (const auto& entry : fs::directory_iterator(inputDir)) {
        if (entry.is_regular_file()) {
            std::string inputPath = entry.path();
            std::string outputPath = outputDir + "/" + entry.path().filename().string();
            encryptFileRSA(inputPath, outputPath, keySize);
        }
    }

    std::cout << "Encryption process done" << std::endl;
}



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
