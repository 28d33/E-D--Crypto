#include <iostream>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void generateRSAKeys(const std::string &publicKeyFile, const std::string &privateKeyFile, int keyLength) {
    // Generate RSA key pair
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    if (BN_set_word(bne, RSA_F4) != 1) { // RSA_F4 is 0x10001, a common public exponent
        std::cerr << "Error initializing big number: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        return;
    }

    if (RSA_generate_key_ex(rsa, keyLength, bne, nullptr) != 1) {
        std::cerr << "Error generating RSA key pair: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        BN_free(bne);
        RSA_free(rsa);
        return;
    }

    // Save public key
    FILE *publicFile = fopen(publicKeyFile.c_str(), "wb");
    if (!publicFile) {
        std::cerr << "Error opening public key file for writing!" << std::endl;
    } else {
        if (PEM_write_RSA_PUBKEY(publicFile, rsa) != 1) {
            std::cerr << "Error writing public key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        } else {
            std::cout << "Public key saved to " << publicKeyFile << std::endl;
        }
        fclose(publicFile);
    }

    // Save private key
    FILE *privateFile = fopen(privateKeyFile.c_str(), "wb");
    if (!privateFile) {
        std::cerr << "Error opening private key file for writing!" << std::endl;
    } else {
        if (PEM_write_RSAPrivateKey(privateFile, rsa, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            std::cerr << "Error writing private key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        } else {
            std::cout << "Private key saved to " << privateKeyFile << std::endl;
        }
        fclose(privateFile);
    }

    // Cleanup
    BN_free(bne);
    RSA_free(rsa);
}

int main() {
    std::string publicKeyFile, privateKeyFile;
    int keyLength;

    std::cout << "Enter the public key file name (.pem): ";
    std::cin >> publicKeyFile;
    std::cout << "Enter the private key file name (.pem): ";
    std::cin >> privateKeyFile;
    std::cout << "Enter the RSA key length (e.g., 2048, 3072, 4096): ";
    std::cin >> keyLength;

    if (keyLength < 2048) {
        std::cerr << "Key length should be at least 2048 bits for security reasons!" << std::endl;
        return 1;
    }

    generateRSAKeys(publicKeyFile, privateKeyFile, keyLength);

    return 0;
}
