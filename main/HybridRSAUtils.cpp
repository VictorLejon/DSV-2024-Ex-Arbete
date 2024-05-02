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
    Botan::PK_Encryptor_EME encryptor(rsaPrivateKey, rng, "EME1(SHA-256)");

    // Generate a random AES key and IV
    Botan::SymmetricKey aesKey(rng, 32); // 256-bit key
    Botan::InitializationVector iv(rng, 16); // 128-bit IV

    // Encrypt the AES key and IV using RSA public key
    std::vector<uint8_t> toEncrypt(aesKey.begin(), aesKey.end());
    toEncrypt.insert(toEncrypt.end(), iv.begin(), iv.end());
    std::vector<uint8_t> encryptedKey = encryptor.encrypt(toEncrypt.data(), toEncrypt.size(), rng);

    // Encrypt the data with AES
    std::unique_ptr<Botan::Cipher_Mode> enc = Botan::Cipher_Mode::create("AES-256/CBC", Botan::Cipher_Dir::Encryption);
    enc->set_key(aesKey);
    enc->start(iv.bits_of());

    std::ifstream inFile(inputFilename, std::ios::binary);
    std::vector<uint8_t> buffer(std::istreambuf_iterator<char>(inFile), {});
    inFile.close();

    enc->finish(buffer);

    // Save the encrypted data
    std::ofstream encryptedDataFile(encryptedDataOutputFilename, std::ios::binary);
    encryptedDataFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    encryptedDataFile.close();

    auto end = std::chrono::high_resolution_clock::now();

    auto inputFileSize = fs::file_size(inputFilename);
    auto outputFileSize = fs::file_size(encryptedDataOutputFilename);

    std::chrono::duration<double, std::milli> encryptionTime = end - start;
    std::cout << "File: " << inputFilename << " encrypted in " << encryptionTime.count() << " milliseconds." << std::endl;
    std::cout << "Input file size: " << inputFileSize << " bytes, Output file size: " << outputFileSize << " bytes." << std::endl;

    // Save the encrypted AES key and IV
    std::ofstream encryptedKeyFile(encryptedKeyOutputFilename, std::ios::binary);
    encryptedKeyFile.write(reinterpret_cast<const char*>(encryptedKey.data()), encryptedKey.size());
    encryptedKeyFile.close();
    std::cout << "AES key written to " << encryptedKeyOutputFilename << std::endl;

    // Write the private key to a file in PKCS#8 PEM format
    std::ofstream privateKeyFile(privateKeyOutputFilename, std::ios::binary);
    privateKeyFile << Botan::PKCS8::PEM_encode(rsaPrivateKey);
    privateKeyFile.close();
    std::cout << "Private RSA key written to " << privateKeyOutputFilename << std::endl;
}


void hybridDecryptFile(const std::string& encryptedDataInputFilename, const std::string& encryptedKeyInputFilename, const std::string& decryptedOutputFilename, const std::string& privateKeyFilename) {
   
    auto start = std::chrono::high_resolution_clock::now();
    Botan::AutoSeeded_RNG rng;

    // Load the RSA private key
    Botan::DataSource_Stream keyFile(privateKeyFilename);
    std::unique_ptr<Botan::Private_Key> privKey(Botan::PKCS8::load_key(keyFile));
    Botan::PK_Decryptor_EME decryptor(*privKey, rng, "EME1(SHA-256)");

    // Read the encrypted AES key and IV
    std::ifstream encryptedKeyFile(encryptedKeyInputFilename, std::ios::binary);
    std::vector<uint8_t> encryptedKey((std::istreambuf_iterator<char>(encryptedKeyFile)), std::istreambuf_iterator<char>());
    encryptedKeyFile.close();

    // Decrypt the AES key and IV
    Botan::secure_vector<uint8_t> decryptedKeyIV = decryptor.decrypt(encryptedKey.data(), encryptedKey.size());

    // Extract the AES key and IV
    Botan::SymmetricKey aesKey(decryptedKeyIV.data(), 32);
    Botan::InitializationVector iv(decryptedKeyIV.data() + 32, 16);

    // Decrypt the data with AES
    std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-256/CBC", Botan::Cipher_Dir::Decryption);
    dec->set_key(aesKey);
    dec->start(iv.bits_of());

    std::ifstream encryptedDataFile(encryptedDataInputFilename, std::ios::binary);
    std::vector<uint8_t> buffer(std::istreambuf_iterator<char>(encryptedDataFile), {});
    encryptedDataFile.close();

    dec->finish(buffer);

    // Save the decrypted data
    std::ofstream decryptedDataFile(decryptedOutputFilename, std::ios::binary);
    decryptedDataFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    decryptedDataFile.close();

    auto end = std::chrono::high_resolution_clock::now();

    auto inputFileSize = fs::file_size(encryptedDataInputFilename);
    auto outputFileSize = fs::file_size(decryptedOutputFilename);

    std::chrono::duration<double, std::milli> decryptionTime = end - start;

    std::cout << "File: " << encryptedDataInputFilename << " decrypted in " << decryptionTime.count() << " milliseconds." << std::endl;
    std::cout << "Input file size: " << inputFileSize << " bytes, Output file size: " << outputFileSize << " bytes." << std::endl;
}


void encryptDirectoryHybridRSA(const std::string& inputDir, const std::string& outputDir) {
    fs::create_directories(outputDir);
    fs::create_directories(outputDir + "/keys");

    for (const auto& entry : fs::directory_iterator(inputDir)) {
        if (entry.is_regular_file()) {
            std::string inputPath = entry.path();
            std::string outputDataFilename = outputDir + "/encrypted_" + entry.path().filename().string();
            std::string outputAESKeyFilename = outputDir + "/keys/aes_encrypted_" + entry.path().filename().string() + ".key";
            std::string outputRSAKeyFilename = outputDir + "/keys/rsa_encrypted_" + entry.path().filename().string() + ".pem";
            hybridEncryptFile(inputPath, outputDataFilename, outputAESKeyFilename, outputRSAKeyFilename);
        }
    }
    std::cout << "Encryption process done. \n" << std::endl;
}


void decryptDirectoryHybridRSA(const std::string& inputDir) {
    fs::create_directories(inputDir + "/decrypted");

    for (const auto& entry : fs::directory_iterator(inputDir)) {
        if (entry.is_regular_file()) {
            std::string inputPath = entry.path();
            std::string inputKeyPath = inputDir + "/keys/aes_" + entry.path().filename().string() + ".key";
            std::string outputFilename = inputDir + "/decrypted/" + "decrypted_" + entry.path().filename().string();
            std::string privKeyPath = inputDir + "/keys/rsa_" + entry.path().filename().string() + ".pem";
            hybridDecryptFile(inputPath, inputKeyPath, outputFilename, privKeyPath);
        }
    }
    std::cout << "Decryption process done. \n" << std::endl;
}


void runTest(const std::string& inputDir, const std::string& outputDir){
    std::string csvPath = "./RES_RSA_AES_" + inputDir + ".csv";
    CSVLogger::initCSV(csvPath);

    encryptDirectoryHybridRSA(inputDir, outputDir);
    decryptDirectoryHybridRSA(outputDir);
}