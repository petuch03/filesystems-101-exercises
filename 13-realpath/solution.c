#include <solution.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

typedef struct {
    char* buffer;
    size_t length;
} PathString;

static void init_path_string(PathString* ps) {
    ps->buffer = malloc(4096);
    ps->length = 0;
    if (ps->buffer) {
        ps->buffer[0] = '/';
        ps->buffer[1] = '\0';
        ps->length = 1;
    } else {
        exit(2);
    }
}

static void append_to_path(PathString* ps, const char* str, size_t len) {
    while (len > 0 && str[0] == '/' && ps->buffer[ps->length - 1] == '/') {
        str++;
        len--;
    }
    if (len == 0) return;
    memcpy(ps->buffer + ps->length, str, len);
    ps->length += len;
    ps->buffer[ps->length] = '\0';
}

static void remove_last_component(PathString* ps) {
    if (ps->length <= 1) return;

    size_t i = ps->length - 2;  // Skip trailing null
    while (i > 0 && ps->buffer[i] != '/') i--;
    ps->length = i + 1;
    ps->buffer[ps->length] = '\0';
}

static int handle_special_dir(PathString* ps, const char* name) {
    if (strcmp(name, "/.") == 0) {
        return 1;
    }
    if (strcmp(name, "/..") == 0) {
        remove_last_component(ps);
        return 1;
    }
    return 0;
}

static int process_symlink(PathString* ps, char* work_buf, char** next_path) {
    ssize_t link_size = readlink(ps->buffer, work_buf, 4095);
    if (link_size <= 0) return 0;

    work_buf[link_size] = '\0';
    if (work_buf[0] == '/') {
        ps->length = 0;
        append_to_path(ps, "/", 1);
        append_to_path(ps, work_buf, strlen(work_buf));
    } else {
        remove_last_component(ps);
        char* new_path = malloc(8192);
        if (!new_path) exit(2);

        if (*next_path) {
            snprintf(new_path, 8192, "/%s%s", work_buf, *next_path);
        } else {
            snprintf(new_path, 8192, "/%s", work_buf);
        }
        *next_path = new_path;
        ps->length = 1;
        ps->buffer[1] = '\0';
    }
    return 1;
}

void abspath(const char* path) {
    PathString result;
    init_path_string(&result);

    char work_buffer[4096];
    char current[4096];
    struct stat st;

    snprintf(work_buffer, sizeof(work_buffer), "%s%s",
             path[0] != '/' ? "/" : "", path);
    char* current_pos = work_buffer;

    while (current_pos) {
        char* next = strchr(current_pos + 1, '/');
        size_t part_len = next ? (size_t)(next - current_pos)
                              : strlen(current_pos);

        memcpy(current, current_pos, part_len);
        current[part_len] = '\0';

        if (handle_special_dir(&result, current)) {
            current_pos = next;
            continue;
        }

        size_t old_len = result.length;
        append_to_path(&result, current, strlen(current));

        if (stat(result.buffer, &st) == -1) {
            result.buffer[old_len] = '\0';
            result.length = old_len;

            if (current[part_len - 1] == '/') {
                current[part_len - 1] = '\0';
            }

            char* component = current + 1;
            if (errno == ENOTDIR && result.length > 1) {
                char* last_sep = strrchr(result.buffer, '/');
                if (last_sep) {
                    component = last_sep + 1;
                    *last_sep = '\0';
                    result.length = strlen(result.buffer);
                }
            }

            report_error(result.length ? result.buffer : "/",
                        component, errno);
            free(result.buffer);
            return;
        }

        if (process_symlink(&result, work_buffer, &current_pos)) {
            continue;
        }

        if (S_ISDIR(st.st_mode) && result.buffer[result.length - 1] != '/') {
            append_to_path(&result, "/", 1);
        }

        current_pos = next;
    }

    report_path(result.buffer);
    free(result.buffer);
}