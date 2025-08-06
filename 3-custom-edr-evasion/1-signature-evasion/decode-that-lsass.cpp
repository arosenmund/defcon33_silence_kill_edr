#include <iostream>
#include <fstream>
#include <vector>

#define XOR_KEY 0x41

int main() {
    std::ifstream inFile("lsass_encoded.bin", std::ios::binary);
    if (!inFile.is_open()) {
        std::cerr << "[-] Failed to open input file.\n";
        return 1;
    }

    std::vector<char> data((std::istreambuf_iterator<char>(inFile)),
                            std::istreambuf_iterator<char>());
    inFile.close();

    // XOR decode
    for (auto& byte : data) {
        byte ^= XOR_KEY;
    }

    std::ofstream outFile("lsass_decoded.dmp", std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << "[-] Failed to open output file.\n";
        return 1;
    }

    outFile.write(data.data(), data.size());
    outFile.close();

    std::cout << "[+] Decoded memory written to lsass_decoded.dmp\n";
    return 0;
}
