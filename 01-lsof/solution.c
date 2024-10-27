#include <solution.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

static void process_fd_directory(const char* pid) {
	char fd_path[512];
	char file_path[512];
	char real_path[4096];
	DIR* fd_dir;
	struct dirent* fd_entry;

	// Open the fd directory for this process
	snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", pid);
	fd_dir = opendir(fd_path);
	if (!fd_dir) {
		report_error(fd_path, errno);
		return;
	}

	// Read each entry in the fd directory
	while ((fd_entry = readdir(fd_dir))) {
		// Skip . and ..
		if (fd_entry->d_name[0] == '.') {
			continue;
		}

		// Create path to the fd symlink
		snprintf(file_path, sizeof(file_path), "/proc/%s/fd/%s",
				pid, fd_entry->d_name);

		// Read the symlink to get the actual file path
		ssize_t len = readlink(file_path, real_path, sizeof(real_path) - 1);
		if (len == -1) {
			report_error(file_path, errno);
			continue;
		}

		real_path[len] = '\0';
		report_file(real_path);
	}

	closedir(fd_dir);
}

void lsof(void) {
	DIR* proc_dir;
	struct dirent* proc_entry;

	proc_dir = opendir("/proc");
	if (!proc_dir) {
		report_error("/proc", errno);
		return;
	}

	while ((proc_entry = readdir(proc_dir))) {
		// Check if the entry is a process directory (numeric name)
		if (proc_entry->d_type == DT_DIR) {
			char* endptr;
			long pid = strtol(proc_entry->d_name, &endptr, 10);

			// Valid process ID found
			if (*endptr == '\0' && pid > 0) {
				process_fd_directory(proc_entry->d_name);
			}
		}
	}

	closedir(proc_dir);
}