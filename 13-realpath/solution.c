#include <solution.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>

#define MAX_PATH_LEN PATH_MAX
#define MAX_SYMLINKS 40

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

static int resolve_path(char *result, size_t *result_len, const char *path, int symlinks_followed) {
    struct stat st;
    char link_buf[MAX_PATH_LEN];
    const char *p = path;
    char parent_path[MAX_PATH_LEN];
    size_t parent_len = 0;

    if (symlinks_followed >= MAX_SYMLINKS) {
        errno = ELOOP;
        return -1;
    }

    if (path[0] == '/') {
        result[1] = '\0';
        *result_len = 1;
        p++;
    }

    while (*p) {
        const char *seg_start = p;
        size_t seg_len = 0;

        // Save parent path
        memcpy(parent_path, result, *result_len);
        parent_len = *result_len;
        parent_path[parent_len] = '\0';

        while (*p && *p != '/') {
            p++;
            seg_len++;
        }

        while (*p == '/') {
            p++;
        }

        if (seg_len > 0) {
            char temp_path[MAX_PATH_LEN];
            size_t temp_len = *result_len;

            memcpy(temp_path, result, temp_len);
            temp_path[temp_len] = '\0';

            if (temp_len > 1) {
                temp_path[temp_len++] = '/';
                temp_path[temp_len] = '\0';
            }

            memcpy(temp_path + temp_len, seg_start, seg_len);
            temp_path[temp_len + seg_len] = '\0';

            if (lstat(temp_path, &st) != 0) {
                if (errno == ENOENT) {
                    // For ENOENT, report the parent path and the failing component
                    report_error(parent_path, seg_start, ENOENT);
                } else {
                    report_error(result, seg_start, errno);
                }
                return -1;
            }

            if (S_ISLNK(st.st_mode)) {
                char new_path[MAX_PATH_LEN];
                ssize_t link_len;
                size_t remaining_len;

                link_len = readlink(temp_path, link_buf, sizeof(link_buf) - 1);
                if (link_len < 0) {
                    report_error(result, seg_start, errno);
                    return -1;
                }
                link_buf[link_len] = '\0';

                if (link_buf[0] == '/') {
                    size_t buf_len = link_len;
                    memcpy(new_path, link_buf, buf_len);
                    new_path[buf_len] = '\0';
                } else {
                    size_t cur_dir_len = *result_len;
                    if (cur_dir_len > 1) {
                        memcpy(new_path, result, cur_dir_len);
                        new_path[cur_dir_len++] = '/';
                    } else {
                        new_path[0] = '/';
                        cur_dir_len = 1;
                    }
                    memcpy(new_path + cur_dir_len, link_buf, link_len);
                    new_path[cur_dir_len + link_len] = '\0';
                }

                remaining_len = strlen(p);
                if (remaining_len > 0) {
                    size_t new_path_len = strlen(new_path);
                    if (new_path[new_path_len - 1] != '/') {
                        new_path[new_path_len++] = '/';
                    }
                    memcpy(new_path + new_path_len, p, remaining_len + 1);
                }

                return resolve_path(result, result_len, new_path, symlinks_followed + 1);
            } else {
                handle_path_segment(result, result_len, seg_start, seg_len);
            }
        }
    }

    return 0;
}

void abspath(const char *path) {
    char result[MAX_PATH_LEN] = "/";
    size_t result_len = 1;
    struct stat st;

    if (resolve_path(result, &result_len, path, 0) == 0) {
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
}