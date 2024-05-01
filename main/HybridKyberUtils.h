#ifndef HYBRID_KYBER_UTILS_H
#define HYBRID_KYBER_UTILS_H

#include <string>

    void hybridKyberEncryptFile(const std::string& inputFilename, 
                                const std::string& encryptedDataOutputFilename, 
                                const std::string& encryptedKeyOutputFilename, 
                                const std::string& publicKeyOutputFilename);

    void hybridKyberDecryptFile(const std::string& encryptedDataInputFilename, 
                                const std::string& encryptedKeyInputFilename, 
                                const std::string& decryptedOutputFilename, 
                                const std::string& privateKeyInputFilename);

    void encryptDirectoryHybridKyber(const std::string& inputDir, 
                                      const std::string& outputDir);

    void decryptDirectoryHybridKyber(const std::string& inputDir);

#endif // HYBRID_KYBER_UTILS_H
