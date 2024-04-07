#include "HybridRSAUtils.h"
#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <botan/pipe.h>
#include <botan/filters.h>
#include <botan/pubkey.h>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

void hybridEncryptFile(const std::string& inputFilename, const std::string& encryptedDataOutputFilename, const std::string& encryptedKeyOutputFilename, const std::string& privateKeyOutputFilename) {
    
    auto start = std::chrono::high_resolution_clock::now();

    Botan::AutoSeeded_RNG rng;

    // Generate RSA key-pair
    Botan::RSA_PrivateKey rsaPrivateKey(rng, 2048);
    Botan::RSA_PublicKey rsaPublicKey = rsaPrivateKey;

    // Generate a random AES key and IV
    Botan::SymmetricKey aesKey(rng, 32); // 256-bit key
    Botan::InitializationVector iv(rng, 16); // 128-bit IV

    // Encrypt the AES key and IV using RSA public key
    Botan::PK_Encryptor_EME encryptor(rsaPublicKey, rng, "EME1(SHA-256)");
    std::vector<uint8_t> toEncrypt(aesKey.begin(), aesKey.end());
    toEncrypt.insert(toEncrypt.end(), iv.begin(), iv.end());
    std::vector<uint8_t> encryptedKey = encryptor.encrypt(toEncrypt.data(), toEncrypt.size(), rng);

    // Encrypt the data with AES
    Botan::Pipe pipe(Botan::get_cipher("AES-256/CBC", aesKey, iv, Botan::ENCRYPTION));
    std::ifstream inFile(inputFilename, std::ios::binary);
    if (!inFile) {
        throw std::runtime_error("Could not open input file for reading: " + inputFilename);
    }
    pipe.start_msg();
    inFile >> pipe;
    inFile.close();
    pipe.end_msg();

    // Save the encrypted data
    std::ofstream encryptedDataFile(encryptedDataOutputFilename, std::ios::out | std::ios::binary);
    if (!encryptedDataFile) {
        throw std::runtime_error("Could not open encrypted data file for writing: " + encryptedDataOutputFilename);
    }
    pipe.set_default_msg(0);
    encryptedDataFile << pipe;
    encryptedDataFile.close();

    auto end = std::chrono::high_resolution_clock::now();

    // Save the encrypted AES key and IV
    std::ofstream encryptedKeyFile(encryptedKeyOutputFilename, std::ios::out | std::ios::binary);
    if (!encryptedKeyFile) {
        throw std::runtime_error("Could not open encrypted key file for writing: " + encryptedKeyOutputFilename);
    }
    
    encryptedKeyFile.write(reinterpret_cast<const char*>(encryptedKey.data()), encryptedKey.size());
    encryptedKeyFile.close();

    // Write the private key to a file in PKCS#8 PEM format
    std::ofstream privateKeyFile(privateKeyOutputFilename, std::ios::out | std::ios::binary);
    if (!privateKeyFile) {
        throw std::runtime_error("Could not open private key file for writing: " + privateKeyOutputFilename);
    }
    privateKeyFile << Botan::PKCS8::PEM_encode(rsaPrivateKey);
    privateKeyFile.close();
}

/*
void hybridDecryptFile(const std::string& encryptedDataInputFilename, const std::string& encryptedKeyInputFilename, const std::string& decryptedOutputFilename, const std::string& privateKeyFilename) {
    Botan::AutoSeeded_RNG rng;

    // Load the RSA private key
    Botan::DataSource_Stream keyFile(privateKeyFilename);
    std::unique_ptr<Botan::Private_Key> privKey(Botan::PKCS8::load_key(keyFile, rng));
    Botan::PK_Decryptor_EME decryptor(*privKey, rng, "EME1(SHA-256)");

    // Read the encrypted AES key and IV
    std::ifstream encryptedKeyFile(encryptedKeyInputFilename, std::ios::binary);
    std::vector<uint8_t> encryptedKey((std::istreambuf_iterator<char>(encryptedKeyFile)), std::istreambuf_iterator<char>());
    encryptedKeyFile.close();

    // Decrypt the AES key and IV
    std::vector<uint8_t> decryptedKeyIV = decryptor.decrypt(encryptedKey.data(), encryptedKey.size());

    // Extract the AES key and IV
    Botan::SymmetricKey aesKey(&decryptedKeyIV[0], 32);
    Botan::InitializationVector iv(&decryptedKeyIV[32], 16);

    // Decrypt the data with AES
    Botan::Pipe pipe(Botan::get_cipher("AES-256/CBC", aesKey, iv, Botan::DECRYPTION));
    std::ifstream encryptedDataFile(encryptedDataInputFilename, std::ios::binary);
    pipe.start_msg();
    encryptedDataFile >> pipe;
    encryptedDataFile.close();
    pipe.end_msg();

    // Save the decrypted data
    std::ofstream decryptedDataFile(decryptedOutputFilename, std::ios::out | std::ios::binary);
    pipe.set_default_msg(0);
    decryptedDataFile << pipe;
    decryptedDataFile.close();
}

*/

/*

void generateRSAKeyPair(const std::string& publicKeyFilename, const std::string& privateKeyFilename, size_t keySize) {
    Botan::AutoSeeded_RNG rng;
    Botan::RSA_PrivateKey rsaKey(rng, keySize);

    // Save the private key
    std::ofstream outFile(privateKeyFilename, std::ios::out | std::ios::binary);
    outFile << Botan::PKCS8::PEM_encode(rsaKey);
    outFile.close();

    // Save the public key
    std::ofstream outPubFile(publicKeyFilename, std::ios::out | std::ios::binary);
    outPubFile << Botan::X509::PEM_encode(rsaKey);
    outPubFile.close();
}
*/

void encryptDirectoryHybridRSA(const std::string& inputDir, const std::string& outputDir) {
    fs::create_directories(outputDir);
    fs::create_directories(outputDir + "/keys");

    for (const auto& entry : fs::directory_iterator(inputDir)) {
        if (entry.is_regular_file()) {
            std::string inputPath = entry.path();
            std::string outputDataFilename = outputDir + "/encrypted_" + entry.path().filename().string() + ".bin";
            std::string outputAESKeyFilename = outputDir + "/keys/aes_" + entry.path().filename().string() + ".bin";
            std::string outputRSAKeyFilename = outputDir + "/keys/rsa_" + entry.path().filename().string() + ".pem";
            hybridEncryptFile(inputPath, outputDataFilename, outputAESKeyFilename, outputRSAKeyFilename);
        }
    }
}

/*
void hybridDecryptDirectory(const std::string& inputDir, const std::string& outputDir) {
    fs::create_directories(outputDir);

    Botan::AutoSeeded_RNG rng;
    Botan::DataSource_Stream in(privateKeyFilename);
    std::unique_ptr<Botan::Private_Key> privKey(Botan::PKCS8::load_key(in, rng));

    for (const auto& entry : fs::directory_iterator(inputDir)) {
        if (entry.is_regular_file() && entry.path().extension() != ".key") {
            std::string inputPath = entry.path();
            std::string inputKeyPath = inputPath + ".key";
            std::string outputFilename = outputDir + "/decrypted_" + entry.path().filename().string();
            hybridDecryptFile(inputPath, inputKeyPath, outputFilename, *privKey, rng);
        }
    }
}
*/