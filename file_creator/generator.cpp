#include <iostream>
#include <fstream>
#include <random>
#include <sstream>
#include <filesystem>
namespace fs = std::filesystem;

void generateBinaryFile(const std::string& filename, std::size_t fileSize, std::string& dataSet) {
    std::ofstream file(dataSet + "/" + filename, std::ios::binary | std::ios::out);
    if (!file) {
        std::cerr << "Cannot open the file: " << filename << std::endl;
        return;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (std::size_t i = 0; i < fileSize; ++i) {
        char byte = static_cast<char>(dis(gen));
        file.write(&byte, sizeof(byte));
    }

    file.close();
    std::cout << "File \"" << filename << "\" has been created with " << fileSize << " random bytes." << std::endl;
}

int main() {
    std::size_t maxFileSize;
    std::string dataSet;
    int step;
    //std::cout << "Enter the maximum size of the binary file in bytes: ";
    std::cin >> maxFileSize >> step >> dataSet;
    dataSet = "files/" + dataSet;
    int fileCount;

    for (std::size_t fileSize = step; fileSize <= maxFileSize; fileSize += step) {
        fileCount++;
        std::stringstream ss;
        ss << "random_file_" << fileSize << ".bin";
        fs::create_directory(dataSet);
        generateBinaryFile(ss.str(), fileSize, dataSet);
    }

    std::cout << "Generated " << fileCount <<" files with sizes up to " << maxFileSize << " bytes in steps of " << step << " bytes." << std::endl;

    return 0;
}
