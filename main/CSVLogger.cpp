#include "CSVLogger.h"
#include <fstream>
#include <iostream>

namespace CSVLogger {

    void initCSV(const std::string& filePath) {
        std::ofstream file(filePath);
        file << "Filename,Time (ms)\n";
        file.close();
    }

    void logData(const std::string& filePath, const std::string& data) {
        std::ofstream file(filePath, std::ios_base::app);
        file << data << "\n";
        file.close();
    }
}
