
#pragma once
#include <string>
#include <fstream>

inline void WriteLog(const std::string& message) {
    std::ofstream logFile("lsass_dumper.log", std::ios::app);
    logFile << message << std::endl;
}
