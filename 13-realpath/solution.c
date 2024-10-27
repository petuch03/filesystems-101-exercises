#include <solution.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>

#define MAX_PATH_LEN PATH_MAX

static void handle_path_segment(char *result, size_t *result_len, const char *segment, size_t seg_len) {
    if (seg_len == 0 || (seg_len == 1 && segment[0] == '.')) {
        return;
    }

    if (seg_len == 2 && segment[0] == '.' && segment[1] == '.') {
        while (*result_len > 1 && result[*result_len - 1] == '/') {
            (*result_len)--;
        }
        while (*result_len > 1 && result[*result_len - 1] != '/') {
            (*result_len)--;
        }
        result[*result_len] = '\0';
        return;
    }

    if (*result_len > 1) {
        result[*result_len] = '/';
        (*result_len)++;
    }

    memcpy(result + *result_len, segment, seg_len);
    *result_len += seg_len;
    result[*result_len] = '\0';
}

static void process_path_component(char *result, size_t *result_len, const char *component, size_t len) {
    const char *p = component;
    const char *end = component + len;
    const char *seg_start;

    while (p < end) {
        while (p < end && *p == '/') {
            p++;
        }

        seg_start = p;

        while (p < end && *p != '/') {
            p++;
        }

        if (p > seg_start) {
            handle_path_segment(result, result_len, seg_start, p - seg_start);
        }
    }
}

void abspath(const char *path) {
    char result[MAX_PATH_LEN] = "/";
    size_t result_len = 1;
    struct stat st;
    char link_buf[MAX_PATH_LEN];
    const char *p = path;

    if (path[0] == '/') {
        p++;
    }

    while (*p) {
        const char *seg_start = p;
        size_t seg_len = 0;

        while (*p && *p != '/') {
            p++;
            seg_len++;
        }

        while (*p == '/') {
            p++;
        }

        if (seg_len > 0) {
            char temp_path[MAX_PATH_LEN];
            size_t temp_len = result_len;

            memcpy(temp_path, result, result_len);
            temp_path[temp_len] = '\0';
            if (result_len > 1) {
                temp_path[temp_len++] = '/';
                temp_path[temp_len] = '\0';
            }

            memcpy(temp_path + temp_len, seg_start, seg_len);
            temp_path[temp_len + seg_len] = '\0';

            if (lstat(temp_path, &st) != 0) {
                report_error(result, seg_start, errno);
                return;
            }

            if (S_ISLNK(st.st_mode)) {
                ssize_t link_len = readlink(temp_path, link_buf, sizeof(link_buf) - 1);
                if (link_len < 0) {
                    report_error(result, seg_start, errno);
                    return;
                }
                link_buf[link_len] = '\0';

                if (link_buf[0] == '/') {
                    result[1] = '\0';
                    result_len = 1;
                    process_path_component(result, &result_len, link_buf + 1, link_len - 1);
                } else {
                    process_path_component(result, &result_len, link_buf, link_len);
                }
            } else {
                handle_path_segment(result, &result_len, seg_start, seg_len);
            }
        }
    }

    if (stat(result, &st) != 0) {
        report_error("/", result + 1, errno);
        return;
    }

    if (S_ISDIR(st.st_mode) && result[result_len - 1] != '/') {
        result[result_len++] = '/';
        result[result_len] = '\0';
    }

    report_path(result);
}