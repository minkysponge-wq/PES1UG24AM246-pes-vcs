// index.c — Staging area implementation
//
// Text format of .pes/index (one entry per line, sorted by path):
//
//   <mode-octal> <64-char-hex-hash> <mtime-seconds> <size> <path>
//
// Example:
//   100644 a1b2c3d4e5f6...  1699900000 42 README.md
//   100644 f7e8d9c0b1a2...  1699900100 128 src/main.c
//
// This is intentionally a simple text format. No magic numbers, no
// binary parsing. The focus is on the staging area CONCEPT (tracking
// what will go into the next commit) and ATOMIC WRITES (temp+rename).
//
// PROVIDED functions: index_find, index_remove, index_status
// TODO functions:     index_load, index_save, index_add

#include "index.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <inttypes.h>

// Forward declaration (implemented in object.c)
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ─── PROVIDED ────────────────────────────────────────────────────────────────

// Find an index entry by path (linear scan).
IndexEntry* index_find(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0)
            return &index->entries[i];
    }
    return NULL;
}

// Remove a file from the index.
// Returns 0 on success, -1 if path not in index.
int index_remove(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0) {
            int remaining = index->count - i - 1;
            if (remaining > 0)
                memmove(&index->entries[i], &index->entries[i + 1],
                        remaining * sizeof(IndexEntry));
            index->count--;
            return index_save(index);
        }
    }
    fprintf(stderr, "error: '%s' is not in the index\n", path);
    return -1;
}

// Print the status of the working directory.
int index_status(const Index *index) {
    printf("Staged changes:\n");
    int staged_count = 0;
    for (int i = 0; i < index->count; i++) {
        printf("  staged:     %s\n", index->entries[i].path);
        staged_count++;
    }
    if (staged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Unstaged changes:\n");
    int unstaged_count = 0;
    for (int i = 0; i < index->count; i++) {
        struct stat st;
        if (stat(index->entries[i].path, &st) != 0) {
            printf("  deleted:    %s\n", index->entries[i].path);
            unstaged_count++;
        } else {
            if (st.st_mtime != (time_t)index->entries[i].mtime_sec || st.st_size != (off_t)index->entries[i].size) {
                printf("  modified:   %s\n", index->entries[i].path);
                unstaged_count++;
            }
        }
    }
    if (unstaged_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    printf("Untracked files:\n");
    int untracked_count = 0;
    DIR *dir = opendir(".");
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
            if (strcmp(ent->d_name, ".pes") == 0) continue;
            if (strcmp(ent->d_name, "pes") == 0) continue;
            if (strstr(ent->d_name, ".o") != NULL) continue;

            int is_tracked = 0;
            for (int i = 0; i < index->count; i++) {
                if (strcmp(index->entries[i].path, ent->d_name) == 0) {
                    is_tracked = 1; 
                    break;
                }
            }
            
            if (!is_tracked) {
                struct stat st;
                stat(ent->d_name, &st);
                if (S_ISREG(st.st_mode)) {
                    printf("  untracked:  %s\n", ent->d_name);
                    untracked_count++;
                }
            }
        }
        closedir(dir);
    }
    if (untracked_count == 0) printf("  (nothing to show)\n");
    printf("\n");

    return 0;
}

// ─── TODO: Implement these ───────────────────────────────────────────────────

// Load the index from .pes/index.
int index_load(Index *index) {
    index->count = 0;

    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) {
        // No index file yet = empty staging area (not an error)
        return 0;
    }

    char line[1024];
    while (fgets(line, sizeof(line), f) != NULL) {
        if (index->count >= MAX_INDEX_ENTRIES) break;

        IndexEntry *e = &index->entries[index->count];

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
        e->mtime_sec = mtime;
        e->size = size;
        snprintf(e->path, sizeof(e->path), "%s", path);

        index->count++;
    }

    fclose(f);
    return 0;
}

// qsort comparator: sort entries by path
static int compare_index_entries(const void *a, const void *b) {
    return strcmp(((const IndexEntry *)a)->path, ((const IndexEntry *)b)->path);
}

// Save the index to .pes/index atomically.
// Use a static buffer for the sorted copy to avoid stack overflow
// (Index is ~5MB, too big for the stack).
int index_save(const Index *index) {
    static Index sorted;
    memcpy(&sorted, index, sizeof(Index));
    qsort(sorted.entries, sorted.count, sizeof(IndexEntry), compare_index_entries);

    const char *tmp_path = ".pes/index.tmp";
    FILE *f = fopen(tmp_path, "w");
    if (!f) return -1;

    for (int i = 0; i < sorted.count; i++) {
        const IndexEntry *e = &sorted.entries[i];
        char hex[HASH_HEX_SIZE + 1];
        hash_to_hex(&e->hash, hex);

        fprintf(f, "%o %s %" PRIu64 " %u %s\n",
                e->mode, hex, e->mtime_sec, e->size, e->path);
    }

    if (fflush(f) != 0) { fclose(f); return -1; }
    if (fsync(fileno(f)) != 0) { fclose(f); return -1; }
    if (fclose(f) != 0) return -1;

    if (rename(tmp_path, INDEX_FILE) != 0) return -1;

    return 0;
}

// Stage a file: read it, write blob to object store, update index entry.
int index_add(Index *index, const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "error: cannot stat '%s'\n", path);
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "error: '%s' is not a regular file\n", path);
        return -1;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "error: cannot open '%s'\n", path);
        return -1;
    }

    size_t file_size = (size_t)st.st_size;
    void *data = malloc(file_size > 0 ? file_size : 1);
    if (!data) { fclose(f); return -1; }

    if (file_size > 0 && fread(data, 1, file_size, f) != file_size) {
        free(data);
        fclose(f);
        return -1;
    }
    fclose(f);

    ObjectID blob_id;
    if (object_write(OBJ_BLOB, data, file_size, &blob_id) != 0) {
        free(data);
        return -1;
    }
    free(data);

    uint32_t mode = 0100644;
    if (st.st_mode & S_IXUSR) mode = 0100755;

    IndexEntry *existing = index_find(index, path);
    if (existing) {
        existing->mode = mode;
        existing->hash = blob_id;
        existing->mtime_sec = (uint64_t)st.st_mtime;
        existing->size = (uint32_t)file_size;
    } else {
        if (index->count >= MAX_INDEX_ENTRIES) {
            fprintf(stderr, "error: index is full\n");
            return -1;
        }
        IndexEntry *e = &index->entries[index->count++];
        e->mode = mode;
        e->hash = blob_id;
        e->mtime_sec = (uint64_t)st.st_mtime;
        e->size = (uint32_t)file_size;
        snprintf(e->path, sizeof(e->path), "%s", path);
    }

    return index_save(index);
}