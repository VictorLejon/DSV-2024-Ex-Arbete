// RSAUtils.h
#ifndef RSA_UTILS_H
#define RSA_UTILS_H

#include <botan/rsa.h>
#include <string>

void encryptFileRSA(const std::string& inputFilename, const std::string& outputFilename, size_t keySize);
void decryptFileRSA(const std::string& inputFilename, const std::string& outputFilename, const Botan::RSA_PrivateKey& privateKey);
void encryptDirectoryRSA(const std::string& inputDir, const std::string& outputDir, size_t keySize);
void decryptDirectoryRSA(const std::string& inputDir, const std::string& outputDir, const Botan::RSA_PrivateKey& privateKey);

#endif // RSA_UTILS_H
