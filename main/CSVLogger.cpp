#include "CSVLogger.h"
#include <fstream>
#include <iostream>

namespace CSVLogger {

    void initCSV(const std::string& filePath) {
        std::ofstream file(filePath);
        file << "Filename,Encryption Time (ms),Decryption Time (ms)\n";
        file.close();
    }

    void logData(const std::string& filePath, const std::vector<std::string>& data) {
        std::ofstream file(filePath, std::ios_base::app);
        for (const auto& line : data) {
            file << line << "\n";
        }
        file.close();
    }
}
