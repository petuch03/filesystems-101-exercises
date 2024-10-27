#include <solution.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#define CHUNK_SIZE 2048

typedef struct {
    char* data;
    size_t capacity;
    size_t used;
} DynamicBuffer;

typedef struct {
    char** items;
    size_t capacity;
    size_t count;
} StringArray;

static DynamicBuffer* create_buffer(void) {
    DynamicBuffer* buf = malloc(sizeof(DynamicBuffer));
    if (!buf) return NULL;

    buf->data = malloc(CHUNK_SIZE);
    if (!buf->data) {
        free(buf);
        return NULL;
    }

    buf->capacity = CHUNK_SIZE;
    buf->used = 0;
    return buf;
}

static StringArray* create_string_array(void) {
    StringArray* arr = malloc(sizeof(StringArray));
    if (!arr) return NULL;

    arr->items = malloc(CHUNK_SIZE * sizeof(char*));
    if (!arr->items) {
        free(arr);
        return NULL;
    }

    arr->capacity = CHUNK_SIZE;
    arr->count = 0;
    return arr;
}

static int expand_buffer(DynamicBuffer* buf) {
    size_t new_size = buf->capacity * 2;
    char* new_data = realloc(buf->data, new_size);
    if (!new_data) return 0;

    buf->data = new_data;
    buf->capacity = new_size;
    return 1;
}

static int expand_array(StringArray* arr) {
    size_t new_size = arr->capacity * 2;
    char** new_items = realloc(arr->items, new_size * sizeof(char*));
    if (!new_items) return 0;

    arr->items = new_items;
    arr->capacity = new_size;
    return 1;
}

static void free_buffer(DynamicBuffer* buf) {
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

static void free_string_array(StringArray* arr) {
    if (arr) {
        for (size_t i = 0; i < arr->count; i++) {
            free(arr->items[i]);
        }
        free(arr->items);
        free(arr);
    }
}

static DynamicBuffer* read_file_content(const char* path) {
    FILE* file = fopen(path, "r");
    if (!file) return NULL;

    DynamicBuffer* buf = create_buffer();
    if (!buf) {
        fclose(file);
        return NULL;
    }

    while (1) {
        if (buf->used >= buf->capacity && !expand_buffer(buf)) break;

        size_t bytes = fread(buf->data + buf->used, 1,
                           buf->capacity - buf->used, file);
        if (bytes == 0) break;
        buf->used += bytes;
    }

    fclose(file);
    return buf;
}

static StringArray* split_null_terminated(DynamicBuffer* buf) {
    StringArray* arr = create_string_array();
    if (!arr) return NULL;

    char* current = buf->data;
    char* end = buf->data + buf->used;

    while (current < end) {
        if (arr->count >= arr->capacity - 1 && !expand_array(arr)) {
            free_string_array(arr);
            return NULL;
        }

        arr->items[arr->count] = strdup(current);
        if (!arr->items[arr->count]) {
            free_string_array(arr);
            return NULL;
        }

        arr->count++;
        current += strlen(current) + 1;
    }

    arr->items[arr->count] = NULL;
    return arr;
}

static void process_single_pid(const char* name) {
    char path[512];
    char exe_result[4096];
    DynamicBuffer *cmd_buf = NULL, *env_buf = NULL;
    StringArray *args = NULL, *env = NULL;

    // Read executable path
    snprintf(path, sizeof(path), "/proc/%s/exe", name);
    ssize_t exe_length = readlink(path, exe_result, sizeof(exe_result) - 1);
    if (exe_length < 0) {
        report_error(path, errno);
        return;
    }
    exe_result[exe_length] = '\0';

    // Read command line
    snprintf(path, sizeof(path), "/proc/%s/cmdline", name);
    cmd_buf = read_file_content(path);
    if (!cmd_buf) {
        report_error(path, errno);
        return;
    }

    args = split_null_terminated(cmd_buf);
    if (!args) goto cleanup;

    // Read environment
    snprintf(path, sizeof(path), "/proc/%s/environ", name);
    env_buf = read_file_content(path);
    if (!env_buf) goto cleanup;

    env = split_null_terminated(env_buf);
    if (!env) goto cleanup;

    report_process(atoi(name), exe_result, args->items, env->items);

cleanup:
    free_buffer(cmd_buf);
    free_buffer(env_buf);
    free_string_array(args);
    free_string_array(env);
}

void ps(void) {
    DIR* procdir = opendir("/proc");
    if (!procdir) {
        report_error("/proc", errno);
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(procdir))) {
        if (entry->d_type != DT_DIR) continue;

        char* endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        process_single_pid(entry->d_name);
    }

    closedir(procdir);
}