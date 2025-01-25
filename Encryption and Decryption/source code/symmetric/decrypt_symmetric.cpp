#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <cstring>

void decryptFile(const std::string &inputFile, const std::string &outputFile, const std::vector<unsigned char> &key, const std::vector<unsigned char> &iv) {
    std::ifstream inFile(inputFile, std::ios::binary);
    std::ofstream outFile(outputFile, std::ios::binary);

    if (!inFile.is_open() || !outFile.is_open()) {
        std::cerr << "Error opening files!" << std::endl;
        return;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Error initializing cipher context!" << std::endl;
        return;
    }

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());

    const size_t bufferSize = 4096;
    unsigned char buffer[bufferSize];
    unsigned char plainBuffer[bufferSize + AES_BLOCK_SIZE];
    int bytesRead, plainBytes;

    while ((bytesRead = inFile.read(reinterpret_cast<char *>(buffer), bufferSize).gcount()) > 0) {
        EVP_DecryptUpdate(ctx, plainBuffer, &plainBytes, buffer, bytesRead);
        outFile.write(reinterpret_cast<char *>(plainBuffer), plainBytes);
    }

    EVP_DecryptFinal_ex(ctx, plainBuffer, &plainBytes);
    outFile.write(reinterpret_cast<char *>(plainBuffer), plainBytes);

    EVP_CIPHER_CTX_free(ctx);

    inFile.close();
    outFile.close();
    std::cout << "Decryption complete. Decrypted file: " << outputFile << std::endl;
}

int main() {
    std::string inputFile, outputFile;
    std::cout << "Enter the encrypted file name: ";
    std::cin >> inputFile;
    std::cout << "Enter the output file name: ";
    std::cin >> outputFile;

    std::string keyInput;
    std::cout << "Enter the 32-byte symmetric key (256-bit) used for encryption: ";
    std::cin >> keyInput;

    std::vector<unsigned char> key(32);
    std::memcpy(key.data(), keyInput.c_str(), std::min(keyInput.size(), key.size()));

    std::vector<unsigned char> iv(16, 0); // Initialize IV to zero for simplicity

    decryptFile(inputFile, outputFile, key, iv);

    return 0;
}
