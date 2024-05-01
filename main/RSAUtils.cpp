// RSAUtils.cpp
#include "RSAUtils.h"
#include <botan/pkcs8.h>
#include <botan/data_src.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/x509_key.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <chrono>

namespace fs = std::filesystem;

Botan::RSA_PrivateKey loadPrivateKeyFromFile(const std::string& filename, Botan::RandomNumberGenerator& rng) {
    std::ifstream keyFile(filename, std::ios::in | std::ios::binary);
    if (!keyFile.is_open()) {
        throw std::runtime_error("Could not open private key file: " + filename);
    }
    
    std::ostringstream oss;
    oss << keyFile.rdbuf();
    std::string keyData = oss.str();
    
    // Create a DataSource from the string
    Botan::DataSource_Memory keyDataSource(keyData);
    
    std::unique_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(keyDataSource));
    Botan::RSA_PrivateKey* rsaKey = dynamic_cast<Botan::RSA_PrivateKey*>(key.get());

    if (!rsaKey) {
        throw std::runtime_error("The loaded key is not an RSA private key.");
    }

    // Return a copy of the RSA key to avoid issues when the unique_ptr goes out of scope
    return *rsaKey;
}

void writePrivateKeyToFile(const Botan::RSA_PrivateKey& rsaPrivateKey, const std::string& privateKeyOutputFilename) {

    // Write the private key to a file in PKCS#8 PEM format
    std::ofstream privateKeyFile(privateKeyOutputFilename, std::ios::out | std::ios::binary);
    if (!privateKeyFile) {
        throw std::runtime_error("Could not open private key file for writing: " + privateKeyOutputFilename);
    }
    privateKeyFile << Botan::PKCS8::PEM_encode(rsaPrivateKey);
    privateKeyFile.close();

    std::cout << "Private key written to " << privateKeyOutputFilename << std::endl;
}

void encryptChunkRSA(const Botan::PK_Encryptor_EME& encryptor, std::vector<uint8_t>& buffer, std::ofstream& outFile, unsigned long long& chunkCount) {
    Botan::AutoSeeded_RNG rng;
    std::vector<uint8_t> ciphertext = encryptor.encrypt(buffer.data(), buffer.size(), rng);
    outFile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    chunkCount++; // Increment the chunk counter
}

void encryptFileRSA(const std::string& inputFilename, const std::string& outputDir, const std::string& outputFilename,  size_t keySize) {

    size_t maxChunkSize = keySize == 1024 ? 62 : 190; // Adjust based on key size and padding scheme
    unsigned long long chunkCount = 0; // Initialize chunk counte
    std::string outputPath = outputDir + "/" + outputFilename;

    auto start = std::chrono::high_resolution_clock::now();
    

    Botan::AutoSeeded_RNG rng;
    Botan::RSA_PrivateKey privateKey(rng, keySize);

    Botan::PK_Encryptor_EME encryptor(privateKey, rng, "EME1(SHA-256)");

    std::ifstream inFile(inputFilename, std::ios::binary);
    std::ofstream outFile(outputPath, std::ios::binary);

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
    auto outputFileSize = fs::file_size(outputPath);
    
    std::cout << "File: " << inputFilename << " encrypted in " << encryptionTime.count() << " milliseconds with " << chunkCount << " chunks." << std::endl;
    std::cout << "Input file size: " << inputFileSize << " bytes, Output file size: " << outputFileSize << " bytes." << std::endl;
    writePrivateKeyToFile(privateKey, outputDir + "/keys/" + outputFilename + ".pem"); // Done for decryption purposes, not secure
}

void encryptDirectoryRSA(const std::string& inputDir, const std::string& outputDir, size_t keySize) {
    
    fs::create_directories(outputDir);
    fs::create_directories(outputDir + "/keys");

    for (const auto& entry : fs::directory_iterator(inputDir)) {
        if (entry.is_regular_file()) {
            std::string inputPath = entry.path();
            std::string outputFilename = "encrypted_" + entry.path().filename().string();
            encryptFileRSA(inputPath, outputDir, outputFilename, keySize);
        }
    }

    std::cout << "Encryption process done.\n" << std::endl;
}


void decryptChunkRSA(const Botan::PK_Decryptor_EME& decryptor, std::vector<uint8_t>& buffer, std::ofstream& outFile) {
    auto ciphertext = decryptor.decrypt(buffer.data(), buffer.size());
    std::vector<uint8_t> plaintext(ciphertext.begin(), ciphertext.end());
    outFile.write(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());
}


void decryptFileRSA(const std::string& inputFilename, const std::string& outputFilename, const Botan::RSA_PrivateKey& privateKey, size_t keySize) {

    size_t encryptedChunkSize = keySize == 1024 ? 128 : 256;
    

    auto start = std::chrono::high_resolution_clock::now();

    Botan::AutoSeeded_RNG rng;
    Botan::PK_Decryptor_EME decryptor(privateKey, rng, "EME1(SHA-256)");

    std::ifstream inFile(inputFilename, std::ios::binary);
    std::ofstream outFile(outputFilename, std::ios::binary);

    

    std::vector<uint8_t> buffer(encryptedChunkSize);
    while (inFile.read(reinterpret_cast<char*>(buffer.data()), encryptedChunkSize)) {
        decryptChunkRSA(decryptor, buffer, outFile);
    }

    auto end = std::chrono::high_resolution_clock::now();

    inFile.close();
    outFile.close();

    
    std::chrono::duration<double, std::milli> decryptionTime = end - start;

    auto inputFileSize = fs::file_size(inputFilename);
    auto outputFileSize = fs::file_size(outputFilename);

    std::cout << "File: " << inputFilename << " decrypted in " << decryptionTime.count() << " milliseconds." << std::endl;
    std::cout << "Input file size: " << inputFileSize << " bytes, Output file size: " << outputFileSize << " bytes." << std::endl;
}

void decryptDirectoryRSA(const std::string& outputDir, size_t keySize) {
    fs::create_directories(outputDir + "/decrypted");

    for (const auto& entry : fs::directory_iterator(outputDir)) {
        if (entry.is_regular_file()) {
            std::string inputPath = entry.path();
            std::string outputPath = outputDir + "/decrypted" + "/decrypted_" + entry.path().filename().string();
            Botan::AutoSeeded_RNG rng;
            auto privateKey = loadPrivateKeyFromFile(outputDir + "/keys/" + entry.path().filename().string() + ".pem", rng);
            decryptFileRSA(inputPath, outputPath, privateKey, keySize);
        }
    }
    std::cout << "Decryption process done. \n" << std::endl;
}
