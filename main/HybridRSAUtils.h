#ifndef HYBRID_ENCRYPTION_UTILS_H
#define HYBRID_ENCRYPTION_UTILS_H

#include <string>
#include <botan/rsa.h>
#include <botan/auto_rng.h>

void runTestRSA_AES(const std::string& inputDir, const std::string& outputDir);
void encryptDirectoryHybridRSA(const std::string& inputDir, const std::string& outputDir);
void decryptDirectoryHybridRSA(const std::string& outputDir);
std::string hybridDecryptFile(const std::string& encryptedDataInputFilename, const std::string& encryptedKeyInputFilename, const std::string& decryptedOutputFilename, const std::string& privateKeyFilename);
std::string hybridEncryptFile(const std::string& inputFilename, const std::string& encryptedDataOutputFilename, const std::string& encryptedKeyOutputFilename, const std::string& privateKeyOutputFilename);

#endif // HYBRID_ENCRYPTION_UTILS_H
