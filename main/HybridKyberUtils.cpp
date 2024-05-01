#include "HybridKyberUtils.h"
#include <botan/auto_rng.h>
#include <botan/kyber.h>
#include <botan/block_cipher.h>
#include <botan/asn1_obj.h>
#include <botan/der_enc.h>
#include <botan/exceptn.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <botan/pipe.h>
#include <botan/filters.h>
#include <botan/pubkey.h>
#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;


void hybridKyberEncryptFile(const std::string& inputFilename, const std::string& encryptedDataOutputFilename, const std::string& encryptedKeyOutputFilename, const std::string& privateKeyOutputFilename) {
    
    auto start = std::chrono::high_resolution_clock::now();

    Botan::AutoSeeded_RNG rng;

    // Generate Kyber private key
    Botan::Kyber_PrivateKey priv_key(rng, Botan::KyberMode::Kyber512_R3);

    // Serialize and save the private key using PKCS#8 format
    std::ofstream privateKeyFile(privateKeyOutputFilename, std::ios::out | std::ios::binary);
    privateKeyFile << Botan::PKCS8::PEM_encode(priv_key);
    privateKeyFile.close();

    // Generate public key from the private key
    auto pub_key = priv_key.public_key();

    // Prepare KEM encryptor
    Botan::PK_KEM_Encryptor enc(*pub_key, "KDF2(SHA-256)");

    // Encrypt the shared secret
    auto kem_result = enc.encrypt(rng, 32, {}); // 32 bytes = 256 bits, assuming no salt for simplicity

    // Encrypt data using AES-256/CBC
    Botan::SymmetricKey aesKey(kem_result.shared_key());
    Botan::InitializationVector iv(rng, 16); // 16 bytes = 128 bits IV
    std::unique_ptr<Botan::Cipher_Mode> enc_aes = Botan::Cipher_Mode::create("AES-256/CBC", Botan::Cipher_Dir::Encryption);
    enc_aes->set_key(aesKey);
    enc_aes->start(iv.bits_of());

    std::ifstream inFile(inputFilename, std::ios::binary);
    std::vector<uint8_t> buffer(std::istreambuf_iterator<char>(inFile), {});
    inFile.close();

    enc_aes->finish(buffer);

    auto end = std::chrono::high_resolution_clock::now();

    auto inputFileSize = fs::file_size(inputFilename);
    auto outputFileSize = fs::file_size(encryptedDataOutputFilename);

    std::chrono::duration<double, std::milli> encryptionTime = end - start;
    std::cout << "File: " << inputFilename << " encrypted in " << encryptionTime.count() << " milliseconds." << std::endl;
    std::cout << "Input file size: " << inputFileSize << " bytes, Output file size: " << outputFileSize << " bytes." << std::endl;

    // Save encapsulated key
    std::ofstream encryptedKeyFile(encryptedKeyOutputFilename, std::ios::out | std::ios::binary);
    encryptedKeyFile.write(reinterpret_cast<const char*>(kem_result.encapsulated_shared_key().data()), kem_result.encapsulated_shared_key().size());
    encryptedKeyFile.close();

    // Write encrypted data with IV prepended
    std::ofstream outFile(encryptedDataOutputFilename, std::ios::binary);
    outFile.write(reinterpret_cast<const char*>(iv.begin()), iv.size());
    outFile.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    outFile.close();
}


void hybridKyberDecryptFile(const std::string& encryptedDataInputFilename, const std::string& encryptedKeyInputFilename, const std::string& decryptedOutputFilename, const std::string& privateKeyInputFilename) {
    
    auto start = std::chrono::high_resolution_clock::now();

    Botan::AutoSeeded_RNG rng;

    // Load the private key
    Botan::DataSource_Stream in(privateKeyInputFilename);
    std::unique_ptr<Botan::Private_Key> key(Botan::PKCS8::load_key(in));

    const Botan::Kyber_PrivateKey* kyberKey = dynamic_cast<Botan::Kyber_PrivateKey*>(key.get());

    // Read the encapsulated key
    std::ifstream encryptedKeyFile(encryptedKeyInputFilename, std::ios::binary);
    std::vector<uint8_t> encapsulated_key((std::istreambuf_iterator<char>(encryptedKeyFile)), std::istreambuf_iterator<char>());
    encryptedKeyFile.close();

    // Decapsulate the shared secret
    Botan::PK_KEM_Decryptor kemDecryptor(*kyberKey, rng, "KDF2(SHA-256)");
    auto decrypted_shared_secret = kemDecryptor.decrypt(encapsulated_key, 32, {});

    // Read the encrypted data file including the IV at the beginning
    std::ifstream encryptedDataFile(encryptedDataInputFilename, std::ios::binary);
    std::vector<uint8_t> ivData(16);
    encryptedDataFile.read(reinterpret_cast<char*>(ivData.data()), ivData.size());

    // Continue reading the encrypted data after the IV
    std::vector<uint8_t> encrypted_data(std::istreambuf_iterator<char>(encryptedDataFile), {});
    encryptedDataFile.close();

    // Decrypt the data using AES-256/CBC with the shared secret as the key
    Botan::SymmetricKey aesKey(decrypted_shared_secret.data(), decrypted_shared_secret.size());
    Botan::InitializationVector iv(ivData.data(), ivData.size());
    std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("AES-256/CBC", Botan::Cipher_Dir::Decryption);
    dec->set_key(aesKey);
    dec->start(iv.bits_of());

    dec->finish(encrypted_data);  // In-place decryption

    auto end = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double, std::milli> encryptionTime = end - start;

    // Write the decrypted data
    std::ofstream decryptedDataFile(decryptedOutputFilename, std::ios::binary);
    decryptedDataFile.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
    decryptedDataFile.close();

    std::cout << "File: " << encryptedDataInputFilename << " decrypted in " << encryptionTime.count() << " milliseconds." << std::endl;
}






void encryptDirectoryHybridKyber(const std::string& inputDir, const std::string& outputDir) {
    fs::create_directories(outputDir);
    fs::create_directories(outputDir + "/keys");

    for (const auto& entry : fs::directory_iterator(inputDir)) {
        if (entry.is_regular_file()) {
            std::string inputPath = entry.path();
            std::string outputDataFilename = outputDir + "/encrypted_" + entry.path().filename().string();
            std::string outputKeyFilename = outputDir + "/keys/shared_secret_" + entry.path().filename().string() + ".bin";
            std::string outputPrivateKeyFilename = outputDir + "/keys/private_key_" + entry.path().filename().string() + ".pem";

            hybridKyberEncryptFile(inputPath, outputDataFilename, outputKeyFilename, outputPrivateKeyFilename);
            //std::cout << "Encrypted: " << inputPath << " -> " << outputDataFilename << std::endl;
        }
    }
    std::cout << "Encryption process done. \n" << std::endl;
}


void decryptDirectoryHybridKyber(const std::string& inputDir) {
    std::string outputDir = inputDir + "/decrypted";
    fs::create_directories(outputDir);

    for (const auto& entry : fs::directory_iterator(inputDir)) {
        if (entry.is_regular_file() && entry.path().filename().string().find("encrypted_") != std::string::npos) {
            std::string encryptedFilename = entry.path().filename().string();
            std::string baseFilename = encryptedFilename.substr(10); // Assuming "encrypted_" prefix is 10 characters
            std::string decryptedFilename = outputDir + "/decrypted_" + baseFilename;
            std::string inputKeyFilename = inputDir + "/keys/shared_secret_" + baseFilename + ".bin";
            std::string privateKeyInputFilename = inputDir + "/keys/private_key_" + baseFilename + ".pem";

            hybridKyberDecryptFile(entry.path(), inputKeyFilename, decryptedFilename, privateKeyInputFilename);
        }
    }
    std::cout << "Decryption process done. \n" << std::endl;
}

