#include <iostream>
#include <openssl/rand.h>
#include <iomanip>
#include <vector>

void generateSymmetricKey(size_t keyLength) {
    // Create a vector to hold the key
    std::vector<unsigned char> key(keyLength);

    // Generate random bytes for the key
    if (RAND_bytes(key.data(), keyLength) != 1) {
        std::cerr << "Error generating random bytes for the key." << std::endl;
        return;
    }

    // Print the key in hexadecimal format
    std::cout << "Generated Symmetric Key (" << keyLength * 8 << "-bit):" << std::endl;
    for (size_t i = 0; i < key.size(); ++i) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(key[i]);
    }
    std::cout << std::endl;
}

int main() {
    size_t keyLength;
    std::cout << "Enter the key length in bytes (e.g., 16 for 128-bit, 24 for 192-bit, 32 for 256-bit): ";
    std::cin >> keyLength;

    if (keyLength <= 0) {
        std::cerr << "Key length must be a positive number." << std::endl;
        return 1;
    }

    generateSymmetricKey(keyLength);

    return 0;
}
