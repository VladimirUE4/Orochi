#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

EVP_PKEY *load_public_key(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    return pkey;
}

EVP_PKEY *load_private_key(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);
    return pkey;
}

int aes_encrypt(FILE *infile, FILE *outfile, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new");
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    unsigned char buffer[1024];
    unsigned char ciphertext[1024 + 16];
    int len;
    while (1) {
        size_t read_len = fread(buffer, 1, sizeof(buffer), infile);
        if (read_len <= 0) break;

        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, read_len)) {
            ERR_print_errors_fp(stderr);
            return -1;
        }
        fwrite(ciphertext, 1, len, outfile);
    }

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext, &len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    fwrite(ciphertext, 1, len, outfile);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int aes_decrypt(FILE *infile, FILE *outfile, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        perror("EVP_CIPHER_CTX_new");
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    unsigned char buffer[1024];
    unsigned char plaintext[1024 + 16];
    int len;
    while (1) {
        size_t read_len = fread(buffer, 1, sizeof(buffer), infile);
        if (read_len <= 0) break;

        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, buffer, read_len)) {
            ERR_print_errors_fp(stderr);
            return -1;
        }
        fwrite(plaintext, 1, len, outfile);
    }

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext, &len)) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    fwrite(plaintext, 1, len, outfile);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int main() {
    unsigned char aes_key[16];  // AES 128
    unsigned char iv[16] = "abcdef9876543210";  // InitializationVector  AES-128-CBC
    unsigned char encrypted_aes_key[256];  // Key
    size_t encrypted_key_len;  

    if (!RAND_bytes(aes_key, sizeof(aes_key))) {
        fprintf(stderr, "Error during AES key generation.\n");
        return 1;
    }

    EVP_PKEY *evp_pubkey = load_public_key("public_key.pem");
    if (!evp_pubkey) {
        fprintf(stderr, "Error during RSA public key loading.\n");
        return 1;
    }

    // Cypher AES Key with RSA Public key
    EVP_PKEY_CTX *ctx_encrypt = EVP_PKEY_CTX_new(evp_pubkey, NULL);
    if (!ctx_encrypt) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (EVP_PKEY_encrypt_init(ctx_encrypt) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (EVP_PKEY_encrypt(ctx_encrypt, encrypted_aes_key, &encrypted_key_len, aes_key, sizeof(aes_key)) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("Key AES in (RSA) : ");
    for (int i = 0; i < encrypted_key_len; i++) {
        printf("%02x", encrypted_aes_key[i]);
    }
    printf("\n");


    FILE *infile = fopen("fichierchaud.txt", "rb");
    if (!infile) {
        perror("fopen input_file");
        return 1;
    }

    FILE *outfile = fopen("encrypted_file.tagrandmerelapute", "wb");
    if (!outfile) {
        perror("fopen encrypted_file");
        return 1;
    }


    if (aes_encrypt(infile, outfile, aes_key, iv) != 0) {
        fprintf(stderr, "Error during file encryption\n");
        return 1;
    }


    fclose(infile);
    fclose(outfile);

    EVP_PKEY *evp_privkey = load_private_key("private_key.pem");
    if (!evp_privkey) {
        fprintf(stderr, "Error during RSA private key loading.\n");
        return 1;
    }

    unsigned char decrypted_aes_key[16];
    EVP_PKEY_CTX *ctx_decrypt = EVP_PKEY_CTX_new(evp_privkey, NULL);
    if (!ctx_decrypt) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (EVP_PKEY_decrypt_init(ctx_decrypt) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (EVP_PKEY_decrypt(ctx_decrypt, decrypted_aes_key, &encrypted_key_len, encrypted_aes_key, encrypted_key_len) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    printf("AES Key decrypted : ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", decrypted_aes_key[i]);
    }
    printf("\n");

    infile = fopen("encrypted_file.tagrandmerelapute", "rb");
    if (!infile) {
        perror("fopen encrypted_file");
        return 1;
    }

    outfile = fopen("decrypted_file.txt", "wb");
    if (!outfile) {
        perror("fopen decrypted_file");
        return 1;
    }

    if (aes_decrypt(infile, outfile, decrypted_aes_key, iv) != 0) {
        fprintf(stderr, "Error during file decryption.\n");
        return 1;
    }

    fclose(infile);
    fclose(outfile);

    EVP_PKEY_free(evp_pubkey);
    EVP_PKEY_free(evp_privkey);
    EVP_PKEY_CTX_free(ctx_encrypt);
    EVP_PKEY_CTX_free(ctx_decrypt);

    return 0;
}
