#ifndef HYBRID_KYBER_UTILS_H
#define HYBRID_KYBER_UTILS_H

#include <string>

    std::string hybridKyberEncryptFile(const std::string& inputFilename, 
                                const std::string& encryptedDataOutputFilename, 
                                const std::string& encryptedKeyOutputFilename, 
                                const std::string& publicKeyOutputFilename);

    std::string hybridKyberDecryptFile(const std::string& encryptedDataInputFilename, 
                                const std::string& encryptedKeyInputFilename, 
                                const std::string& decryptedOutputFilename, 
                                const std::string& privateKeyInputFilename);

    void encryptDirectoryHybridKyber(const std::string& inputDir, 
                                      const std::string& outputDir);

    void decryptDirectoryHybridKyber(const std::string& inputDir);

    void runTestKYBER_AES(const std::string& inputDir, const std::string& outputDir);

#endif // HYBRID_KYBER_UTILS_H
