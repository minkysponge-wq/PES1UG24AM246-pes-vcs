// tree.c — Tree object serialization and construction
//
// PROVIDED functions: get_file_mode, tree_parse, tree_serialize
// TODO functions:     tree_from_index
//
// Binary tree format (per entry, concatenated with no separators):
//   "<mode-as-ascii-octal> <n>\0<32-byte-binary-hash>"
//
// Example single entry (conceptual):
//   "100644 hello.txt\0" followed by 32 raw bytes of SHA-256

#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <inttypes.h>

// Forward declaration (implemented in object.c)
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── Mode Constants ─────────────────────────────────────────────────────────

#define MODE_FILE      0100644
#define MODE_EXEC      0100755
#define MODE_DIR       0040000

// ─── PROVIDED ───────────────────────────────────────────────────────────────

// Determine the object mode for a filesystem path.
uint32_t get_file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;

    if (S_ISDIR(st.st_mode))  return MODE_DIR;
    if (st.st_mode & S_IXUSR) return MODE_EXEC;
    return MODE_FILE;
}

// Parse binary tree data into a Tree struct safely.
// Returns 0 on success, -1 on parse error.
int tree_parse(const void *data, size_t len, Tree *tree_out) {
    tree_out->count = 0;
    const uint8_t *ptr = (const uint8_t *)data;
    const uint8_t *end = ptr + len;

    while (ptr < end && tree_out->count < MAX_TREE_ENTRIES) {
        TreeEntry *entry = &tree_out->entries[tree_out->count];

        // 1. Safely find the space character for the mode
        const uint8_t *space = memchr(ptr, ' ', end - ptr);
        if (!space) return -1; // Malformed data

        // Parse mode into an isolated buffer
        char mode_str[16] = {0};
        size_t mode_len = space - ptr;
        if (mode_len >= sizeof(mode_str)) return -1;
        memcpy(mode_str, ptr, mode_len);
        entry->mode = strtol(mode_str, NULL, 8);

        ptr = space + 1; // Skip space

        // 2. Safely find the null terminator for the name
        const uint8_t *null_byte = memchr(ptr, '\0', end - ptr);
        if (!null_byte) return -1; // Malformed data

        size_t name_len = null_byte - ptr;
        if (name_len >= sizeof(entry->name)) return -1;
        memcpy(entry->name, ptr, name_len);
        entry->name[name_len] = '\0'; // Ensure null-terminated

        ptr = null_byte + 1; // Skip null byte

        // 3. Read the 32-byte binary hash
        if (ptr + HASH_SIZE > end) return -1; 
        memcpy(entry->hash.hash, ptr, HASH_SIZE);
        ptr += HASH_SIZE;

        tree_out->count++;
    }
    return 0;
}

// Helper for qsort to ensure consistent tree hashing
static int compare_tree_entries(const void *a, const void *b) {
    return strcmp(((const TreeEntry *)a)->name, ((const TreeEntry *)b)->name);
}

// Serialize a Tree struct into binary format for storage.
// Caller must free(*data_out).
// Returns 0 on success, -1 on error.
int tree_serialize(const Tree *tree, void **data_out, size_t *len_out) {
    // Estimate max size: (6 bytes mode + 1 byte space + 256 bytes name + 1 byte null + 32 bytes hash) per entry
    size_t max_size = tree->count * 296; 
    uint8_t *buffer = malloc(max_size);
    if (!buffer) return -1;

    // Create a mutable copy to sort entries (Git requirement)
    Tree sorted_tree = *tree;
    qsort(sorted_tree.entries, sorted_tree.count, sizeof(TreeEntry), compare_tree_entries);

    size_t offset = 0;
    for (int i = 0; i < sorted_tree.count; i++) {
        const TreeEntry *entry = &sorted_tree.entries[i];
        
        // Write mode and name (%o writes octal correctly for Git standards)
        int written = sprintf((char *)buffer + offset, "%o %s", entry->mode, entry->name);
        offset += written + 1; // +1 to step over the null terminator written by sprintf
        
        // Write binary hash
        memcpy(buffer + offset, entry->hash.hash, HASH_SIZE);
        offset += HASH_SIZE;
    }

    *data_out = buffer;
    *len_out = offset;
    return 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// A lightweight local version of an index entry for tree building.
// We read the .pes/index file directly here so tree.c doesn't depend on index.c.
typedef struct {
    uint32_t mode;
    ObjectID hash;
    char path[512];
} LocalIndexEntry;

#define LOCAL_MAX 10000

// Read the index file into a local array (no dependency on index.c).
static int load_index_local(LocalIndexEntry *entries, int *count_out) {
    *count_out = 0;
    FILE *f = fopen(".pes/index", "r");
    if (!f) return 0; // empty index is fine

    char line[1024];
    while (fgets(line, sizeof(line), f) != NULL) {
        if (*count_out >= LOCAL_MAX) break;

        LocalIndexEntry *e = &entries[*count_out];
        unsigned int mode;
        char hex[HASH_HEX_SIZE + 1];
        uint64_t mtime;
        uint32_t size;
        char path[512];

        int n = sscanf(line, "%o %64s %" SCNu64 " %u %511[^\n]",
                       &mode, hex, &mtime, &size, path);
        if (n != 5) continue;

        e->mode = mode;
        if (hex_to_hash(hex, &e->hash) != 0) continue;
        snprintf(e->path, sizeof(e->path), "%s", path);

        (*count_out)++;
    }
    fclose(f);
    return 0;
}

// Recursive helper: builds a tree from index entries at a given path prefix.
static int build_tree_recursive(const LocalIndexEntry *entries, int entry_count,
                                const char *prefix, size_t prefix_len,
                                ObjectID *id_out) {
    Tree tree;
    tree.count = 0;

    // Track which subdirectories we've already added
    char seen_dirs[MAX_TREE_ENTRIES][256];
    int seen_dir_count = 0;

    for (int i = 0; i < entry_count; i++) {
        const LocalIndexEntry *e = &entries[i];

        // Skip entries that don't belong under this prefix
        if (prefix_len > 0 && strncmp(e->path, prefix, prefix_len) != 0) continue;

        const char *rest = e->path + prefix_len;
        if (*rest == '\0') continue;

        const char *slash = strchr(rest, '/');

        if (slash == NULL) {
            // Direct file in this directory
            if (tree.count >= MAX_TREE_ENTRIES) return -1;
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = e->mode;
            te->hash = e->hash;
            snprintf(te->name, sizeof(te->name), "%s", rest);
        } else {
            // File inside a subdirectory
            size_t dir_name_len = slash - rest;
            if (dir_name_len >= 256) return -1;

            char dir_name[256];
            memcpy(dir_name, rest, dir_name_len);
            dir_name[dir_name_len] = '\0';

            // Already processed?
            int already_seen = 0;
            for (int j = 0; j < seen_dir_count; j++) {
                if (strcmp(seen_dirs[j], dir_name) == 0) {
                    already_seen = 1;
                    break;
                }
            }
            if (already_seen) continue;

            snprintf(seen_dirs[seen_dir_count++], 256, "%s", dir_name);

            // Build new prefix for the recursive call
            char new_prefix[1024];
            snprintf(new_prefix, sizeof(new_prefix), "%.*s%s/",
                     (int)prefix_len, prefix, dir_name);

            // Recurse
            ObjectID sub_id;
            if (build_tree_recursive(entries, entry_count,
                                     new_prefix, strlen(new_prefix),
                                     &sub_id) != 0) {
                return -1;
            }

            // Add the subtree entry
            if (tree.count >= MAX_TREE_ENTRIES) return -1;
            TreeEntry *te = &tree.entries[tree.count++];
            te->mode = MODE_DIR;
            te->hash = sub_id;
            snprintf(te->name, sizeof(te->name), "%s", dir_name);
        }
    }

    // Serialize and write this tree
    void *data;
    size_t len;
    if (tree_serialize(&tree, &data, &len) != 0) return -1;

    int rc = object_write(OBJ_TREE, data, len, id_out);
    free(data);
    return rc;
}

// Build a tree hierarchy from the current index and write all tree
// objects to the object store.
int tree_from_index(ObjectID *id_out) {
    static LocalIndexEntry entries[LOCAL_MAX];
    int count = 0;
    if (load_index_local(entries, &count) != 0) return -1;
    return build_tree_recursive(entries, count, "", 0, id_out);
}