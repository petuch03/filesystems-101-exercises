#include <solution.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>

#define MAX_PATH 4096

static void handle_path_component(char* res, size_t* pos, const char* comp) {
    struct stat st;
    char link_target[MAX_PATH];
    size_t comp_len = strlen(comp);

    if (strcmp(comp, ".") == 0) {
        return;
    }

    if (strcmp(comp, "..") == 0) {
        if (*pos > 1) {
            while (*pos > 1 && res[*pos - 1] == '/') (*pos)--;
            while (*pos > 1 && res[*pos - 1] != '/') (*pos)--;
        }
        return;
    }

    if (res[*pos - 1] != '/') {
        res[*pos] = '/';
        (*pos)++;
    }

    memcpy(res + *pos, comp, comp_len);
    *pos += comp_len;
    res[*pos] = '\0';

    if (lstat(res, &st) != 0) {
        *pos -= comp_len;
        if (*pos > 0 && res[*pos - 1] == '/')
            res[--(*pos)] = '\0';
        res[*pos] = '\0';
        report_error(res[0] == '\0' ? "/" : res, comp, errno);
        exit(1);
    }

    if (S_ISLNK(st.st_mode)) {
        ssize_t link_len = readlink(res, link_target, sizeof(link_target) - 1);
        if (link_len < 0) {
            res[*pos - comp_len - 1] = '\0';
            report_error(res, comp, errno);
            exit(1);
        }
        link_target[link_len] = '\0';

        if (link_target[0] == '/') {
            *pos = 1;
        } else {
            while (*pos > 1 && res[*pos - 1] != '/') (*pos)--;
        }
        res[*pos] = '\0';

        char* save_ptr;
        char* link_copy = strdup(link_target);
        char* link_comp = strtok_r(link_copy, "/", &save_ptr);

        while (link_comp) {
            handle_path_component(res, pos, link_comp);
            link_comp = strtok_r(NULL, "/", &save_ptr);
        }
        free(link_copy);
    }
}

void abspath(const char* path) {
    if (!path || !*path) {
        report_path("/");
        return;
    }

    char res[MAX_PATH];
    size_t pos = 1;
    res[0] = '/';
    res[1] = '\0';

    char* path_copy = strdup(path);
    char* save_ptr;
    char* comp;

    if (path[0] == '/') {
        comp = strtok_r(path_copy + 1, "/", &save_ptr);
    } else {
        comp = strtok_r(path_copy, "/", &save_ptr);
    }

    while (comp) {
        handle_path_component(res, &pos, comp);
        comp = strtok_r(NULL, "/", &save_ptr);
    }

    struct stat st;
    if (pos > 0 && stat(res, &st) == 0 && S_ISDIR(st.st_mode) && res[pos - 1] != '/') {
        res[pos++] = '/';
        res[pos] = '\0';
    }

    free(path_copy);
    report_path(res);
}