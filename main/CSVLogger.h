#pragma once
#include <string>
#include <vector>

namespace CSVLogger {
    void initCSV(const std::string& filePath);
    void logData(const std::string& filePath, const std::vector<std::string>& data);
}
