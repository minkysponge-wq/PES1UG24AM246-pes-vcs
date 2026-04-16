// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // 1. Determine the type string
    const char *type_str;
    if (type == OBJ_BLOB) type_str = "blob";
    else if (type == OBJ_TREE) type_str = "tree";
    else if (type == OBJ_COMMIT) type_str = "commit";
    else return -1;

    // 2. Build the header "type size\0" and then append the data
    char header[64];
    int header_text_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    if (header_text_len < 0) return -1;
    size_t header_len = (size_t)header_text_len + 1; // include the '\0'

    size_t full_len = header_len + len;
    uint8_t *full = (uint8_t *)malloc(full_len);
    if (!full) return -1;
    memcpy(full, header, header_len);
    if (len > 0) memcpy(full + header_len, data, len);

    // 3. Compute SHA-256 of the FULL object (header + data)
    compute_hash(full, full_len, id_out);

    // 4. Deduplication: if it already exists, we're done
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // 5. Build shard directory path and create it
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);
    char shard_dir[512];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755); // ignore error if it already exists

    // 6. Write to a temp file in the same shard directory
    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));
    char tmp_path[600];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", final_path);

    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        free(full);
        return -1;
    }

    size_t total_written = 0;
    while (total_written < full_len) {
        ssize_t n = write(fd, full + total_written, full_len - total_written);
        if (n < 0) {
            close(fd);
            unlink(tmp_path);
            free(full);
            return -1;
        }
        total_written += (size_t)n;
    }

    // 7. fsync to make sure data reaches disk
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp_path);
        free(full);
        return -1;
    }
    close(fd);
    free(full);

    // 8. Atomic rename from temp to final path
    if (rename(tmp_path, final_path) != 0) {
        unlink(tmp_path);
        return -1;
    }

    // 9. fsync the shard directory so the rename is persisted
    int dfd = open(shard_dir, O_RDONLY);
    if (dfd >= 0) {
        fsync(dfd);
        close(dfd);
    }

    return 0;
}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // 1. Build the path from the hash
    char path[512];
    object_path(id, path, sizeof(path));

    // 2. Open the file and read its full contents
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long file_size = ftell(f);
    if (file_size < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }

    uint8_t *buffer = (uint8_t *)malloc((size_t)file_size);
    if (!buffer) { fclose(f); return -1; }

    if (fread(buffer, 1, (size_t)file_size, f) != (size_t)file_size) {
        free(buffer);
        fclose(f);
        return -1;
    }
    fclose(f);

    // 3. Verify integrity: re-hash and compare to the requested hash
    ObjectID computed;
    compute_hash(buffer, (size_t)file_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buffer);
        return -1; // corruption detected
    }

    // 4. Find the null byte separating header from data
    uint8_t *null_byte = memchr(buffer, '\0', (size_t)file_size);
    if (!null_byte) { free(buffer); return -1; }

    // 5. Parse the type string
    if (strncmp((char *)buffer, "blob ", 5) == 0) {
        *type_out = OBJ_BLOB;
    } else if (strncmp((char *)buffer, "tree ", 5) == 0) {
        *type_out = OBJ_TREE;
    } else if (strncmp((char *)buffer, "commit ", 7) == 0) {
        *type_out = OBJ_COMMIT;
    } else {
        free(buffer);
        return -1;
    }

    // 6. Allocate output buffer and copy the data portion
    size_t header_len = (size_t)(null_byte - buffer) + 1; // include the '\0'
    size_t data_len = (size_t)file_size - header_len;

    void *data = malloc(data_len > 0 ? data_len : 1);
    if (!data) { free(buffer); return -1; }
    if (data_len > 0) {
        memcpy(data, buffer + header_len, data_len);
    }

    *data_out = data;
    *len_out = data_len;

    free(buffer);
    return 0;
}