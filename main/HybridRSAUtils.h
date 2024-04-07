#ifndef HYBRID_ENCRYPTION_UTILS_H
#define HYBRID_ENCRYPTION_UTILS_H

#include <string>
#include <botan/rsa.h>
#include <botan/auto_rng.h>

void generateRSAKeyPair(const std::string& publicKeyFilename, const std::string& privateKeyFilename, size_t keySize = 2048);
void encryptDirectoryHybridRSA(const std::string& inputDir, const std::string& outputDir);
void hybridDecryptDirectory(const std::string& inputDir, const std::string& outputDir);
void hybridDecryptFile(const std::string& encryptedDataInputFilename, const std::string& encryptedKeyInputFilename, const std::string& decryptedOutputFilename, const std::string& privateKeyFilename);
void hybridEncryptFile(const std::string& inputFilename, const std::string& encryptedDataOutputFilename, const std::string& encryptedKeyOutputFilename, const std::string& privateKeyOutputFilename);

#endif // HYBRID_ENCRYPTION_UTILS_H
