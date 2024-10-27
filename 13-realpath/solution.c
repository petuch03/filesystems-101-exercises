#include <solution.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>

#define MAX_PATH 4096

static void process_component(char* result, const char* component,
                            int* result_len, const char* curr_path) {
    struct stat st;
    char link_buf[MAX_PATH];
    ssize_t link_len;

    if (strcmp(component, ".") == 0) {
        return;
    }

    if (strcmp(component, "..") == 0) {
        char *last_slash = strrchr(result, '/');
        if (last_slash && last_slash != result) {
            *last_slash = '\0';
            *result_len = last_slash - result;
        }
        return;
    }

    if (result[*result_len - 1] != '/') {
        result[*result_len] = '/';
        (*result_len)++;
    }
    strcpy(result + *result_len, component);
    *result_len += strlen(component);

    if (lstat(result, &st) != 0) {
        char *last_slash = strrchr(result, '/');
        *last_slash = '\0';
        report_error(result, component, errno);
        exit(1);
    }

    if (S_ISLNK(st.st_mode)) {
        link_len = readlink(result, link_buf, sizeof(link_buf) - 1);
        if (link_len == -1) {
            char *last_slash = strrchr(result, '/');
            *last_slash = '\0';
            report_error(result, component, errno);
            exit(1);
        }
        link_buf[link_len] = '\0';

        if (link_buf[0] == '/') {
            *result_len = 0;
            strcpy(result, "/");
            *result_len = 1;
        } else {
            char *last_slash = strrchr(result, '/');
            if (last_slash) {
                *last_slash = '\0';
                *result_len = last_slash - result;
            }
        }

        char *link_copy = strdup(link_buf);
        char *comp = strtok(link_copy, "/");
        while (comp) {
            process_component(result, comp, result_len, curr_path);
            comp = strtok(NULL, "/");
        }
        free(link_copy);
    }
}

void abspath(const char* path) {
    char result[MAX_PATH] = "/";
    int result_len = 1;
    char* path_copy;
    char* component;
    struct stat st;

    if (!path || !*path) {
        report_path("/");
        return;
    }

    path_copy = strdup(path);
    if (path[0] == '/') {
        component = strtok(path_copy + 1, "/");
    } else {
        component = strtok(path_copy, "/");
    }

    while (component) {
        process_component(result, component, &result_len, path);
        component = strtok(NULL, "/");
    }

    if (result_len > 0) {
        if (stat(result, &st) == 0 && S_ISDIR(st.st_mode)) {
            if (result[result_len - 1] != '/') {
                result[result_len] = '/';
                result_len++;
            }
        }
    }

    result[result_len] = '\0';
    free(path_copy);
    report_path(result);
}