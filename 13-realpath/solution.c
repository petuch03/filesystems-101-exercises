#include <solution.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>

#define MAX_PATH 4096

void abspath(const char *path) {
    char *result = malloc(MAX_PATH);
    char initial_path[MAX_PATH];
    char link_buf[MAX_PATH];
    char segment[MAX_PATH];
    struct stat st;
    
    if (!result) exit(2);
    result[0] = '\0';
    
    if (path[0] != '/') {
        snprintf(initial_path, sizeof(initial_path), "/%s", path);
    } else {
        snprintf(initial_path, sizeof(initial_path), "%s", path);
    }
    
    char *current = initial_path;
    while (current) {
        char *next = strchr(current + 1, '/');
        size_t seg_len;
        
        if (next) {
            seg_len = next - current;
        } else {
            seg_len = strlen(current);
        }
        
        memcpy(segment, current, seg_len);
        segment[seg_len] = '\0';
        
        if (strcmp(segment, "/.") == 0) {
            current = next;
            continue;
        }
        
        if (strcmp(segment, "/..") == 0) {
            if (result[0] != '\0') {
                char *last = strrchr(result, '/');
                if (last != NULL) {
                    *last = '\0';
                }
            }
            current = next;
            continue;
        }
        
        if (result[0] != '\0' && result[strlen(result) - 1] == '/' && segment[0] == '/') {
            snprintf(result + strlen(result), MAX_PATH - strlen(result), "%s", segment + 1);
        } else {
            snprintf(result + strlen(result), MAX_PATH - strlen(result), "%s", segment);
        }
        
        ssize_t link_len = readlink(result, link_buf, MAX_PATH - 1);
        if (link_len != -1) {
            link_buf[link_len] = '\0';
            if (link_buf[0] == '/') {
                snprintf(result, MAX_PATH, "%s", link_buf);
            } else {
                char *tmp_path = malloc(MAX_PATH);
                if (!tmp_path) exit(2);
                
                if (next) {
                    snprintf(tmp_path, MAX_PATH, "/%s%s", link_buf, next);
                } else {
                    snprintf(tmp_path, MAX_PATH, "/%s", link_buf);
                }
                
                snprintf(initial_path, MAX_PATH, "%s", tmp_path);
                free(tmp_path);
                result[0] = '\0';
                current = initial_path;
                continue;
            }
        }
        
        if (stat(result, &st) == -1) {
            char curr_component[MAX_PATH];
            snprintf(curr_component, MAX_PATH, "%s", segment + 1);
            
            if (result[0] != '\0') {
                if (result[strlen(result) - 1] == '/') {
                    result[strlen(result) - 1] = '\0';
                }
                char *last = strrchr(result, '/');
                if (last) {
                    *(last + 1) = '\0';
                }
            }
            
            if (curr_component[strlen(curr_component) - 1] == '/') {
                curr_component[strlen(curr_component) - 1] = '\0';
            }
            
            report_error(result[0] == '\0' ? "/" : result, curr_component, errno);
            free(result);
            return;
        }
        
        if (S_ISDIR(st.st_mode) && result[strlen(result) - 1] != '/') {
            snprintf(result + strlen(result), MAX_PATH - strlen(result), "/");
        }
        
        current = next;
    }
    
    report_path(result);
    free(result);
}