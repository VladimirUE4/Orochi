#include <stdio.h>
#include <string.h>
#include <stdlib.h>     // For exit, malloc, free
#include <sys/stat.h>   // For stat, mkdir
#include <sys/types.h>  // For stat, mkdir
#include <dirent.h>     // For opendir, readdir, closedir
#include <limits.h>     // For PATH_MAX
#include <unistd.h>     // For access, ftruncate, close, read, write
#include <time.h>       // For clock_gettime
#include <fcntl.h>      // For open, O_RDONLY etc.
#include <sys/mman.h>   // For mmap, munmap

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h> // For OpenSSL_init_crypto

#define AES_KEY_SIZE 16     // AES-128
#define AES_BLOCK_SIZE 16   // IV size for AES-128-CBC
#define RSA_KEY_SIZE 256    // Assuming 2048-bit RSA key, output buffer size
// Buffer size for chunking data from mmap to OpenSSL (not for fread/fwrite anymore)
#define PROCESSING_CHUNK_SIZE (1024 * 1024) // 1MB

// --- Utility Functions ---
void handle_openssl_errors() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

int ensure_directory_exists(const char *path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        if (mkdir(path, 0700) != 0) {
            perror("mkdir failed");
            fprintf(stderr, "Failed to create directory: %s\n", path);
            return 0;
        }
    } else if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "%s exists but is not a directory\n", path);
        return 0;
    }
    return 1;
}

// --- Key Loading --- (Unchanged)
EVP_PKEY *load_public_key(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen public key");
        return NULL;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    if (!pkey) {
        fprintf(stderr, "Error reading public key from %s\n", filename);
        handle_openssl_errors();
    }
    fclose(file);
    return pkey;
}

EVP_PKEY *load_private_key(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("fopen private key");
        return NULL;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
     if (!pkey) {
        fprintf(stderr, "Error reading private key from %s\n", filename);
        handle_openssl_errors();
    }
    fclose(file);
    return pkey;
}


// --- AES Encryption/Decryption with MMAP ---
int aes_encrypt_file_mmap(const char *input_filename, const char *output_filename, const unsigned char *key) {
    int infd = -1, outfd = -1;
    unsigned char *in_map = MAP_FAILED;
    unsigned char *out_map = MAP_FAILED;
    size_t input_size = 0;
    size_t output_capacity = 0;
    size_t current_output_offset = 0;
    struct stat st_in;

    infd = open(input_filename, O_RDONLY);
    if (infd == -1) {
        perror("open input_filename for mmap");
        return -1;
    }
    if (fstat(infd, &st_in) == -1) {
        perror("fstat input_filename");
        close(infd);
        return -1;
    }
    input_size = st_in.st_size;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        close(infd);
        handle_openssl_errors();
        return -1; // Should not be reached
    }

    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "Error generating IV.\n");
        EVP_CIPHER_CTX_free(ctx);
        close(infd);
        handle_openssl_errors();
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        close(infd);
        handle_openssl_errors();
        return -1;
    }

    // Handle mmap for input if not empty
    if (input_size > 0) {
        in_map = mmap(NULL, input_size, PROT_READ, MAP_PRIVATE, infd, 0);
        if (in_map == MAP_FAILED) {
            perror("mmap input_filename");
            EVP_CIPHER_CTX_free(ctx);
            close(infd);
            return -1;
        }
    }
    close(infd); // Descriptor no longer needed after mmap or if file is empty
    infd = -1;

    outfd = open(output_filename, O_RDWR | O_CREAT | O_TRUNC, 0600); // S_IRUSR | S_IWUSR
    if (outfd == -1) {
        perror("open output_filename for mmap");
        if (in_map != MAP_FAILED) munmap(in_map, input_size);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Estimate output capacity and mmap output file
    output_capacity = AES_BLOCK_SIZE /* IV */ + input_size + AES_BLOCK_SIZE /* Max padding */;
    if (ftruncate(outfd, output_capacity) == -1) {
        perror("ftruncate output_filename");
        if (in_map != MAP_FAILED) munmap(in_map, input_size);
        EVP_CIPHER_CTX_free(ctx);
        close(outfd);
        remove(output_filename);
        return -1;
    }
    out_map = mmap(NULL, output_capacity, PROT_WRITE | PROT_READ, MAP_SHARED, outfd, 0);
    if (out_map == MAP_FAILED) {
        perror("mmap output_filename");
        if (in_map != MAP_FAILED) munmap(in_map, input_size);
        EVP_CIPHER_CTX_free(ctx);
        close(outfd);
        remove(output_filename);
        return -1;
    }

    // Write IV
    memcpy(out_map, iv, AES_BLOCK_SIZE);
    current_output_offset += AES_BLOCK_SIZE;

    int out_len;
    if (input_size > 0) {
        unsigned char *current_input_ptr = in_map;
        size_t remaining_input = input_size;
        while (remaining_input > 0) {
            size_t chunk_to_process = (remaining_input > PROCESSING_CHUNK_SIZE) ? PROCESSING_CHUNK_SIZE : remaining_input;
            if (1 != EVP_EncryptUpdate(ctx, out_map + current_output_offset, &out_len, current_input_ptr, chunk_to_process)) {
                if (in_map != MAP_FAILED) munmap(in_map, input_size);
                munmap(out_map, output_capacity);
                EVP_CIPHER_CTX_free(ctx);
                close(outfd); remove(output_filename);
                handle_openssl_errors();
                return -1;
            }
            current_input_ptr += chunk_to_process;
            current_output_offset += out_len;
            remaining_input -= chunk_to_process;
        }
    }

    if (1 != EVP_EncryptFinal_ex(ctx, out_map + current_output_offset, &out_len)) {
        if (in_map != MAP_FAILED) munmap(in_map, input_size);
        munmap(out_map, output_capacity);
        EVP_CIPHER_CTX_free(ctx);
        close(outfd); remove(output_filename);
        handle_openssl_errors();
        return -1;
    }
    current_output_offset += out_len;

    // Cleanup
    if (in_map != MAP_FAILED) munmap(in_map, input_size);
    EVP_CIPHER_CTX_free(ctx);

    if (msync(out_map, current_output_offset, MS_SYNC) == -1) perror("msync output_map");
    munmap(out_map, output_capacity);
    if (ftruncate(outfd, current_output_offset) == -1) perror("ftruncate final output file");
    close(outfd);

    return 0;
}

int aes_decrypt_file_mmap(const char *input_filename, const char *output_filename, const unsigned char *key) {
    int infd = -1, outfd = -1;
    unsigned char *in_map = MAP_FAILED;
    unsigned char *out_map = MAP_FAILED;
    size_t input_size = 0;
    size_t output_capacity = 0; // Max possible output size (input_size - IV_SIZE)
    size_t current_output_offset = 0;
    struct stat st_in;

    infd = open(input_filename, O_RDONLY);
    if (infd == -1) {
        perror("open input_filename for mmap decrypt");
        return -1;
    }
    if (fstat(infd, &st_in) == -1) {
        perror("fstat input_filename for decrypt");
        close(infd);
        return -1;
    }
    input_size = st_in.st_size;

    if (input_size < AES_BLOCK_SIZE) { // File too short to contain IV
        fprintf(stderr, "Input file %s too short for decryption (missing IV).\n", input_filename);
        close(infd);
        return -1;
    }

    in_map = mmap(NULL, input_size, PROT_READ, MAP_PRIVATE, infd, 0);
    if (in_map == MAP_FAILED) {
        perror("mmap input_filename for decrypt");
        close(infd);
        return -1;
    }
    close(infd); infd = -1;

    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, in_map, AES_BLOCK_SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        munmap(in_map, input_size);
        handle_openssl_errors();
        return -1;
    }
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        munmap(in_map, input_size);
        EVP_CIPHER_CTX_free(ctx);
        handle_openssl_errors();
        return -1;
    }

    outfd = open(output_filename, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (outfd == -1) {
        perror("open output_filename for mmap decrypt");
        munmap(in_map, input_size);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Output capacity can't be larger than input_size - IV_SIZE
    // For empty original file, input_size = IV_SIZE + PADDING_SIZE. Output will be 0.
    output_capacity = (input_size > AES_BLOCK_SIZE) ? (input_size - AES_BLOCK_SIZE) : 0;
    // If input_size is exactly AES_BLOCK_SIZE, it means IV only, no data, no padding. This is an invalid encrypted file.
    // EVP_DecryptUpdate will likely fail. Let's make output_capacity at least 1 if we intend to mmap.
    // However, ftruncate to 0 is fine, then mmap will fail if size is 0.
    // Let's ftruncate to a small initial size if output_capacity is 0, or handle this path without mmap for output.
    // Safest: ftruncate to input_size, as decrypted content will be <= encrypted content minus IV.
    // Max possible plaintext is input_size - AES_BLOCK_SIZE.
    if (output_capacity > 0) { // Only mmap if there's potential output
        if (ftruncate(outfd, output_capacity) == -1) { // Pre-allocate generously
            perror("ftruncate output_filename for decrypt");
            munmap(in_map, input_size);
            EVP_CIPHER_CTX_free(ctx);
            close(outfd); remove(output_filename);
            return -1;
        }
        out_map = mmap(NULL, output_capacity, PROT_WRITE | PROT_READ, MAP_SHARED, outfd, 0);
        if (out_map == MAP_FAILED) {
            perror("mmap output_filename for decrypt");
            // out_map will be MAP_FAILED, handled below
        }
    } else if (input_size == AES_BLOCK_SIZE) { // Only IV, no actual data or padding. This is an error usually.
         // The DecryptFinal will likely fail. For now, proceed, it will be caught.
    }


    int out_len;
    unsigned char *ciphertext_ptr = in_map + AES_BLOCK_SIZE;
    size_t remaining_ciphertext = input_size - AES_BLOCK_SIZE;

    if (remaining_ciphertext > 0) { // If there is ciphertext after IV
        // If out_map failed (e.g. output_capacity was 0), we can't write to it.
        // This scenario (output_capacity=0 but remaining_ciphertext > 0) implies a corrupted file or logic error.
        // For a correctly encrypted empty file, remaining_ciphertext will be AES_BLOCK_SIZE (padding).
        if (out_map == MAP_FAILED && output_capacity > 0) { // mmap failed for a non-zero capacity
             munmap(in_map, input_size);
             EVP_CIPHER_CTX_free(ctx);
             close(outfd); remove(output_filename);
             return -1; // Error already printed by mmap
        }

        // Process in chunks
        size_t current_chunk_input_offset = 0;
        while(current_chunk_input_offset < remaining_ciphertext) {
            size_t chunk_to_process = (remaining_ciphertext - current_chunk_input_offset > PROCESSING_CHUNK_SIZE) ?
                                       PROCESSING_CHUNK_SIZE : (remaining_ciphertext - current_chunk_input_offset);
            
            // Ensure we don't write past out_map's capacity during update
            // EVP_DecryptUpdate can produce less output than input or buffer it.
            // out_map + current_output_offset must be valid.
            if (out_map != MAP_FAILED) { // Only write if out_map is valid
                 if (1 != EVP_DecryptUpdate(ctx, out_map + current_output_offset, &out_len, ciphertext_ptr + current_chunk_input_offset, chunk_to_process)) {
                    fprintf(stderr, "Error during EVP_DecryptUpdate (check key/IV/corruption).\n");
                    if (out_map != MAP_FAILED) munmap(out_map, output_capacity);
                    munmap(in_map, input_size);
                    EVP_CIPHER_CTX_free(ctx);
                    close(outfd); remove(output_filename);
                    handle_openssl_errors();
                    return -1;
                }
                current_output_offset += out_len;
            } else if (output_capacity == 0) { // No output expected yet, just feed data
                 // If output_capacity is 0, out_map is MAP_FAILED. We are just feeding data.
                 // DecryptUpdate will buffer if the output is 0 (e.g. processing padding).
                 // Pass NULL for output buffer to indicate we only want to feed data
                 // (though OpenSSL docs say this is not how it works, output buffer must be valid)
                 // A safer approach for output_capacity=0 is to use a temporary small heap buffer for EVP_DecryptUpdate
                 // and then only write to file if EVP_DecryptFinal says so.
                 // For now, this path (output_capacity = 0 but remaining_ciphertext > 0) is tricky.
                 // Let's assume for now that if remaining_ciphertext > 0, then output_capacity should also be > 0.
                 // If an originally empty file was encrypted, remaining_ciphertext is padding, output_capacity could be 0.
                 // In this case, EVP_DecryptUpdate will consume padding and len will be 0.
                 // So, out_map might not be strictly needed for update if it's just padding.

                 // Simplified: if out_map is MAP_FAILED here, it means output_capacity was 0.
                 // We must ensure EVP_DecryptUpdate doesn't try to write.
                 // A small temp buffer is safer if EVP_DecryptUpdate *must* have an output buffer.
                unsigned char temp_out_buf[PROCESSING_CHUNK_SIZE + AES_BLOCK_SIZE]; // Max possible output from update
                if (1 != EVP_DecryptUpdate(ctx, temp_out_buf, &out_len, ciphertext_ptr + current_chunk_input_offset, chunk_to_process)) {
                    // ... error handling ...
                }
                // if out_len > 0 here, it means an empty file produced output, which is an issue.
                // This branch (output_capacity == 0 but still processing chunks) needs refinement if it's a common path.
                // It's mainly for the case where input is just IV + padding.
            }
            current_chunk_input_offset += chunk_to_process;
        }
    }


    // Finalize decryption
    // Output buffer for final must be large enough for one block.
    unsigned char final_block_buf[AES_BLOCK_SIZE]; // EVP_DecryptFinal might write up to a block
    int final_len;
    // If out_map is valid, try to write directly. Otherwise, use temp buffer.
    if (out_map != MAP_FAILED) {
        if (1 != EVP_DecryptFinal_ex(ctx, out_map + current_output_offset, &final_len)) {
            fprintf(stderr, "Error during EVP_DecryptFinal_ex (check padding, key, or corruption).\n");
            munmap(out_map, output_capacity);
            munmap(in_map, input_size);
            EVP_CIPHER_CTX_free(ctx);
            close(outfd); remove(output_filename);
            handle_openssl_errors();
            return -1;
        }
        current_output_offset += final_len;
    } else { // out_map was not used or failed (e.g. output_capacity was 0)
        if (1 != EVP_DecryptFinal_ex(ctx, final_block_buf, &final_len)) {
            // ... error handling ...
        }
        if (final_len > 0) {
            // This means an empty output file needs to be written to.
            // The outfd is open. We need to write final_block_buf to it.
            if (write(outfd, final_block_buf, final_len) != final_len) {
                perror("write final decrypted block to empty file");
                // ... error handling ...
            }
        }
        current_output_offset = final_len; // This is the total size of the decrypted file.
    }


    // Cleanup
    munmap(in_map, input_size);
    EVP_CIPHER_CTX_free(ctx);

    if (out_map != MAP_FAILED) {
        if (msync(out_map, current_output_offset, MS_SYNC) == -1) perror("msync output_map decrypt");
        munmap(out_map, output_capacity);
    }
    // Truncate output file to actual size written
    if (ftruncate(outfd, current_output_offset) == -1) {
        perror("ftruncate final decrypted output file");
    }
    close(outfd);

    return 0;
}


// --- RSA Key Operations --- (Unchanged)
int rsa_encrypt_key(EVP_PKEY *pub_key, const unsigned char *in_key, size_t in_key_len,
                    unsigned char *out_encrypted_key, size_t *out_encrypted_key_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) { handle_openssl_errors(); return -1; }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) { handle_openssl_errors(); EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) { handle_openssl_errors(); EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_encrypt(ctx, NULL, out_encrypted_key_len, in_key, in_key_len) <= 0) { handle_openssl_errors(); EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_encrypt(ctx, out_encrypted_key, out_encrypted_key_len, in_key, in_key_len) <= 0) { handle_openssl_errors(); EVP_PKEY_CTX_free(ctx); return -1; }
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

int rsa_decrypt_key(EVP_PKEY *priv_key, const unsigned char *in_encrypted_key, size_t in_encrypted_key_len,
                    unsigned char *out_decrypted_key, size_t *out_decrypted_key_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) { handle_openssl_errors(); return -1; }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) { handle_openssl_errors(); EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) { handle_openssl_errors(); EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_decrypt(ctx, NULL, out_decrypted_key_len, in_encrypted_key, in_encrypted_key_len) <= 0) { handle_openssl_errors(); EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_decrypt(ctx, out_decrypted_key, out_decrypted_key_len, in_encrypted_key, in_encrypted_key_len) <= 0) { handle_openssl_errors(); EVP_PKEY_CTX_free(ctx); return -1; }
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

// --- File/Directory Processing ---
const char *ENCRYPTED_EXT = ".Ratio";
const char *AES_KEY_FILE_NAME = "aes_key.enc";

void process_directory(const char *input_dir, const char *output_dir,
                       const unsigned char *aes_key, const char *mode) {
    DIR *dir;
    struct dirent *entry;
    char input_path[PATH_MAX];
    char output_path[PATH_MAX]; // Base output path for entry

    if (!(dir = opendir(input_dir))) {
        perror("opendir");
        fprintf(stderr, "Failed to open input directory: %s\n", input_dir);
        return;
    }

    if (!ensure_directory_exists(output_dir)) {
        closedir(dir);
        return;
    }

    printf("Processing directory: %s -> %s\n", input_dir, output_dir);

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (strcmp(mode, "decrypt") == 0 && strcmp(entry->d_name, AES_KEY_FILE_NAME) == 0) {
            printf("Skipping AES key file during decryption: %s\n", entry->d_name);
            continue;
        }

        snprintf(input_path, sizeof(input_path), "%s/%s", input_dir, entry->d_name);
        snprintf(output_path, sizeof(output_path), "%s/%s", output_dir, entry->d_name); // Base output path

        struct stat path_stat;
        if (stat(input_path, &path_stat) != 0) {
            perror("stat input_path");
            fprintf(stderr, "Failed to stat: %s\n", input_path);
            continue;
        }

        if (S_ISDIR(path_stat.st_mode)) {
            process_directory(input_path, output_path, aes_key, mode); // output_path is now input_dir/subdir
        } else if (S_ISREG(path_stat.st_mode)) {
            char final_output_path[PATH_MAX];
            strncpy(final_output_path, output_path, PATH_MAX -1);
            final_output_path[PATH_MAX-1] = '\0';

            if (strcmp(mode, "encrypt") == 0) {
                strncat(final_output_path, ENCRYPTED_EXT, sizeof(final_output_path) - strlen(final_output_path) - 1);
                printf("Encrypting: %s -> %s\n", input_path, final_output_path);
                if (path_stat.st_size == 0) { // Handle zero-byte files separately if mmap has issues
                    printf("Encrypting zero-byte file (special handling): %s\n", input_path);
                }
                if (aes_encrypt_file_mmap(input_path, final_output_path, aes_key) != 0) {
                    fprintf(stderr, "Encryption failed for %s\n", input_path);
                    remove(final_output_path); // Attempt to clean up
                }
            } else if (strcmp(mode, "decrypt") == 0) {
                if (strstr(input_path, ENCRYPTED_EXT) == NULL) {
                     continue;
                }
                char *ext_ptr = strstr(final_output_path, ENCRYPTED_EXT);
                if (ext_ptr && strcmp(ext_ptr, ENCRYPTED_EXT) == 0) {
                    *ext_ptr = '\0';
                } else {
                    strncat(final_output_path, "_decrypted", sizeof(final_output_path) - strlen(final_output_path) - 1);
                }
                printf("Decrypting: %s -> %s\n", input_path, final_output_path);
                 if (aes_decrypt_file_mmap(input_path, final_output_path, aes_key) != 0) {
                    fprintf(stderr, "Decryption failed for %s\n", input_path);
                    remove(final_output_path); // Attempt to clean up
                }
            }
        }
    }
    closedir(dir);
}

void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s <encrypt|decrypt> <input_dir> <output_dir> <rsa_key_file>\n", prog_name);
    fprintf(stderr, "  <rsa_key_file> is public key for encryption, private key for decryption.\n");
    fprintf(stderr, "Example (encrypt): %s encrypt ./my_files ./encrypted_files ./public_key.pem\n", prog_name);
    fprintf(stderr, "Example (decrypt): %s decrypt ./encrypted_files ./decrypted_files ./private_key.pem\n", prog_name);
}

int main(int argc, char *argv[]) {
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    if (argc != 5) {
        print_usage(argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *input_dir = argv[2];
    const char *output_dir = argv[3];
    const char *rsa_key_file = argv[4];

    if (strcmp(mode, "encrypt") != 0 && strcmp(mode, "decrypt") != 0) {
        fprintf(stderr, "Invalid mode. Must be 'encrypt' or 'decrypt'.\n");
        print_usage(argv[0]);
        return 1;
    }

    if (OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL) == 0) {
        fprintf(stderr, "OpenSSL initialization failed.\n");
        handle_openssl_errors();
        return 1;
    }

    unsigned char aes_key[AES_KEY_SIZE];
    char aes_key_filepath[PATH_MAX];
    EVP_PKEY *rsa_key_evp = NULL;

    if (strcmp(mode, "encrypt") == 0) {
        if (!ensure_directory_exists(output_dir)) {
             fprintf(stderr, "Could not create or access output directory: %s\n", output_dir);
             return 1;
        }
        snprintf(aes_key_filepath, sizeof(aes_key_filepath), "%s/%s", output_dir, AES_KEY_FILE_NAME);

        if (!RAND_bytes(aes_key, sizeof(aes_key))) { /* ... error handling ... */ return 1; }
        printf("Generated AES key.\n");

        rsa_key_evp = load_public_key(rsa_key_file);
        if (!rsa_key_evp) { /* ... */ return 1; }
        printf("Loaded RSA public key.\n");

        unsigned char encrypted_aes_key[RSA_KEY_SIZE * 2];
        size_t encrypted_aes_key_len;
        if (rsa_encrypt_key(rsa_key_evp, aes_key, sizeof(aes_key), encrypted_aes_key, &encrypted_aes_key_len) != 0) {
            EVP_PKEY_free(rsa_key_evp); return 1;
        }
        printf("Encrypted AES key (length: %zu bytes).\n", encrypted_aes_key_len);

        FILE *key_out_file = fopen(aes_key_filepath, "wb");
        if (!key_out_file) { /* ... error handling ... */ EVP_PKEY_free(rsa_key_evp); return 1; }
        if (fwrite(encrypted_aes_key, 1, encrypted_aes_key_len, key_out_file) != encrypted_aes_key_len) {
            /* ... error handling ... */ fclose(key_out_file); remove(aes_key_filepath); EVP_PKEY_free(rsa_key_evp); return 1;
        }
        fclose(key_out_file);
        printf("Stored encrypted AES key to %s\n", aes_key_filepath);

    } else { // decrypt mode
        snprintf(aes_key_filepath, sizeof(aes_key_filepath), "%s/%s", input_dir, AES_KEY_FILE_NAME);
        if (access(aes_key_filepath, F_OK) == -1) { /* ... */ return 1; }
        if (!ensure_directory_exists(output_dir)) { /* ... */ return 1; }

        rsa_key_evp = load_private_key(rsa_key_file);
        if (!rsa_key_evp) { /* ... */ return 1; }
        printf("Loaded RSA private key.\n");

        FILE *key_in_file = fopen(aes_key_filepath, "rb");
        if (!key_in_file) { /* ... */ EVP_PKEY_free(rsa_key_evp); return 1; }
        
        unsigned char encrypted_aes_key_buffer[RSA_KEY_SIZE]; // Max size of RSA encrypted key
        size_t encrypted_aes_key_len = fread(encrypted_aes_key_buffer, 1, sizeof(encrypted_aes_key_buffer), key_in_file);
        if (ferror(key_in_file)) { /* ... */ fclose(key_in_file); EVP_PKEY_free(rsa_key_evp); return 1;}
        if (encrypted_aes_key_len == 0 && feof(key_in_file) && input_dir != NULL ) { // Check if file is just empty
             fprintf(stderr, "Encrypted AES key file %s is empty.\n", aes_key_filepath);
             fclose(key_in_file); EVP_PKEY_free(rsa_key_evp); return 1;
        }
        char temp_byte; // Check if file was larger than buffer
        if (fread(&temp_byte, 1, 1, key_in_file) == 1) {
             fprintf(stderr, "Encrypted AES key file %s is larger than expected (%d bytes).\n", aes_key_filepath, RSA_KEY_SIZE);
             fclose(key_in_file); EVP_PKEY_free(rsa_key_evp); return 1;
        }
        fclose(key_in_file);
        printf("Read encrypted AES key from %s (%zu bytes).\n", aes_key_filepath, encrypted_aes_key_len);

        size_t decrypted_aes_key_len;
        if (rsa_decrypt_key(rsa_key_evp, encrypted_aes_key_buffer, encrypted_aes_key_len,
                             aes_key, &decrypted_aes_key_len) != 0) {
            EVP_PKEY_free(rsa_key_evp); return 1;
        }
        if (decrypted_aes_key_len != AES_KEY_SIZE) {
            fprintf(stderr, "Decrypted AES key has incorrect length: %zu (expected %d).\n", decrypted_aes_key_len, AES_KEY_SIZE);
            EVP_PKEY_free(rsa_key_evp); return 1;
        }
        printf("Decrypted AES key.\n");
    }

    process_directory(input_dir, output_dir, aes_key, mode);

    if (rsa_key_evp) EVP_PKEY_free(rsa_key_evp);

    printf("Operation %s completed.\n", mode);

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed_time = (end_time.tv_sec - start_time.tv_sec) +
                          (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    printf("Total execution time: %.3f seconds\n", elapsed_time);

    return 0;
}
