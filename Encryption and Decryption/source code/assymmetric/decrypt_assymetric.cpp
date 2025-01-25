#include <iostream>
#include <fstream>
#include <vector>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

void decryptFile(const std::string &inputFile, const std::string &outputFile, const std::string &privateKeyFile) {
    // Load the private key
    FILE *keyFile = fopen(privateKeyFile.c_str(), "rb");
    if (!keyFile) {
        std::cerr << "Error opening private key file!" << std::endl;
        return;
    }
    RSA *rsa = PEM_read_RSAPrivateKey(keyFile, nullptr, nullptr, nullptr);
    fclose(keyFile);
    if (!rsa) {
        std::cerr << "Error loading private key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
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
    std::vector<unsigned char> inputBuffer(rsaSize);
    std::vector<unsigned char> decryptedBuffer(rsaSize);

    while (inFile.read(reinterpret_cast<char *>(inputBuffer.data()), rsaSize) || inFile.gcount() > 0) {
        int inputLength = inFile.gcount();
        int decryptedLength = RSA_private_decrypt(inputLength, inputBuffer.data(), decryptedBuffer.data(), rsa, RSA_PKCS1_OAEP_PADDING);
        if (decryptedLength == -1) {
            std::cerr << "Error decrypting data: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            break;
        }
        outFile.write(reinterpret_cast<char *>(decryptedBuffer.data()), decryptedLength);
    }

    RSA_free(rsa);
    inFile.close();
    outFile.close();
    std::cout << "File successfully decrypted: " << outputFile << std::endl;
}

int main() {
    std::string inputFile, outputFile, privateKeyFile;
    std::cout << "Enter the encrypted file name: ";
    std::cin >> inputFile;
    std::cout << "Enter the output (decrypted) file name: ";
    std::cin >> outputFile;
    std::cout << "Enter the private key file name (e.g., private.pem): ";
    std::cin >> privateKeyFile;

    decryptFile(inputFile, outputFile, privateKeyFile);

    return 0;
}
