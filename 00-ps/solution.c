#include <solution.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_PATH_LEN 1024
#define MAX_ARGS 512
#define MAX_BUF_SIZE 16384

static void process_cmdline(const char *filename, char **args, size_t *count) {
    FILE *fp = fopen(filename, "r");
    if (!fp) return;

    char buffer[MAX_BUF_SIZE];
    *count = 0;
    size_t bytes = fread(buffer, 1, sizeof(buffer) - 1, fp);
    fclose(fp);

    if (bytes > 0) {
        char *curr = buffer;
        while (*count < MAX_ARGS - 1 && curr < buffer + bytes) {
            args[*count] = strdup(curr);
            if (!args[*count]) break;
            curr += strlen(curr) + 1;
            (*count)++;
        }
    }
    args[*count] = NULL;
}

static void get_process_info(const char *pid_str) {
    char path[MAX_PATH_LEN];
    char exe_buf[MAX_PATH_LEN];
    char *argv[MAX_ARGS] = {NULL};
    char *envp[MAX_ARGS] = {NULL};
    size_t argc = 0, envc = 0;

    // Get executable path
    snprintf(path, sizeof(path), "/proc/%s/exe", pid_str);
    ssize_t len = readlink(path, exe_buf, sizeof(exe_buf) - 1);
    if (len < 0) {
        report_error(path, errno);
        return;
    }
    exe_buf[len] = '\0';

    // Get command line
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid_str);
    process_cmdline(path, argv, &argc);
    if (!argc) {
        report_error(path, errno);
        return;
    }

    // Get environment
    snprintf(path, sizeof(path), "/proc/%s/environ", pid_str);
    process_cmdline(path, envp, &envc);

    // Report process info
    report_process(atoi(pid_str), exe_buf, argv, envp);

    // Cleanup
    for (size_t i = 0; i < argc; i++) {
        free(argv[i]);
    }
    for (size_t i = 0; i < envc; i++) {
        free(envp[i]);
    }
}

void ps(void) {
    DIR *dir = opendir("/proc");
    if (!dir) {
        report_error("/proc", errno);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        // Check if entry is a process directory
        if (entry->d_type != DT_DIR)
            continue;

        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0)
            continue;

        get_process_info(entry->d_name);
    }

    closedir(dir);
}