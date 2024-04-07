// RSAUtils.h
#ifndef RSA_UTILS_H
#define RSA_UTILS_H

#include <botan/rsa.h>
#include <string>

Botan::RSA_PrivateKey loadPrivateKeyFromFile(const std::string& filename, Botan::RandomNumberGenerator& rng);
void writePrivateKeyToFile(const Botan::RSA_PrivateKey& privateKey, const std::string& filename);
void encryptFileRSA(const std::string& inputFilename, const std::string& outputDir, const std::string& outputFilename, size_t keySize);
void decryptFileRSA(const std::string& inputFilename, const std::string& outputFilename, const Botan::RSA_PrivateKey& privateKey, size_t keySize);
void encryptDirectoryRSA(const std::string& inputDir, const std::string& outputDir, size_t keySize);
void decryptDirectoryRSA(const std::string& inputDir, const std::string& outputDir, size_t keySize);


#endif // RSA_UTILS_H
