#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

void encryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &publicKeyFile) {
    // Load the public key
    FILE *keyFile = fopen(publicKeyFile.c_str(), "rb");
    if (!keyFile) {
        std::cerr << "Error opening public key file!" << std::endl;
        return;
    }
    RSA *rsa = PEM_read_RSA_PUBKEY(keyFile, nullptr, nullptr, nullptr);
    fclose(keyFile);
    if (!rsa) {
        std::cerr << "Error loading public key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return;
    }

    std::ifstream inFile(inputFile, std::ios::binary);
    std::ofstream outFile(outputFile, std::ios::binary);

    if (!inFile.is_open() || !outFile.is_open()) {
        std::cerr << "Error opening input/output file!" << std::endl;
        RSA_free(rsa);
        return;
    }

    const size_t rsaSize = RSA_size(rsa);
    const size_t blockSize = rsaSize - 42; // RSA_PKCS1_OAEP_PADDING
    std::vector<unsigned char> inputBuffer(blockSize);
    std::vector<unsigned char> encryptedBuffer(rsaSize);

    while (inFile.read(reinterpret_cast<char *>(inputBuffer.data()), blockSize) || inFile.gcount() > 0) {
        int inputLength = inFile.gcount();
        int encryptedLength = RSA_public_encrypt(inputLength, inputBuffer.data(), encryptedBuffer.data(), rsa, RSA_PKCS1_OAEP_PADDING);
        if (encryptedLength == -1) {
            std::cerr << "Error encrypting data: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            break;
        }
        outFile.write(reinterpret_cast<char *>(encryptedBuffer.data()), encryptedLength);
    }

    RSA_free(rsa);
    inFile.close();
    outFile.close();
    std::cout << "File successfully encrypted: " << outputFile << std::endl;
}

int main() {
    std::string inputFile, outputFile, publicKeyFile;
    std::cout << "Enter the input file name: ";
    std::cin >> inputFile;
    std::cout << "Enter the output (encrypted) file name: ";
    std::cin >> outputFile;
    std::cout << "Enter the public key file name (e.g., public.pem): ";
    std::cin >> publicKeyFile;

    encryptFile(inputFile, outputFile, publicKeyFile);

    return 0;
}
