#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/types.h>

// Get the current stack pointer (sp) for the thread using PTRACE_GETREGSET
long get_stack_pointer(pid_t pid, pid_t tid) {
    // Attach to the thread to inspect its registers
    if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) == -1) {
        perror("ptrace attach");
        return -1;
    }
    waitpid(tid, NULL, 0); // Wait for the thread to stop

    // Define the register set structure for AArch64
    struct iovec iov;
    struct user_pt_regs regs;  // 34 registers for AArch64 (x0-x30, sp, pc, etc.)
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);

    // Retrieve the register set for the thread
    if (ptrace(PTRACE_GETREGSET, tid, 1, &iov) == -1) {
        perror("ptrace getregset");
        ptrace(PTRACE_DETACH, tid, NULL, NULL);
        return -1;
    }

    // The stack pointer (sp) is stored in regs[31] for AArch64
    long sp = regs.sp; // `sp` is in register 31 for AArch64
    long pc = regs.pc; // `sp` is in register 31 for AArch64

    printf("PC %016lx\n", pc);

    // Detach from the thread
    ptrace(PTRACE_DETACH, tid, NULL, NULL);

    return sp;
}

void dump_stack(pid_t pid, pid_t tid) {
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/task/%d/maps", pid, tid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror("fopen maps");
        return;
    }

    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd == -1) {
        perror("open mem");
        fclose(maps);
        return;
    }

    // Get the current stack pointer for this thread
    long sp = get_stack_pointer(pid, tid);
    if (sp == -1) {
        fclose(maps);
        close(mem_fd);
        return;
    }

    printf("Thread %d stack pointer: 0x%lx\n", tid, sp);

    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5], path[512] = "";
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %511[^\n]", &start, &end, perms, path) >= 3) {
            if (strstr(path, "[stack]")) {
                printf("Thread %d stack region: 0x%lx - 0x%lx\n", tid, start, end);

                // Check if the stack pointer is within this region
                if (sp >= start && sp < end) {
                    printf("Stack pointer is inside the stack region.\n");
                } else {
                    printf("Stack pointer is outside the stack region.\n");
                }

                // Read the memory and save the stack contents
                size_t size = end - start;
                void *buffer = malloc(size);
                if (!buffer) {
                    perror("malloc");
                    continue;
                }

                ssize_t nread = pread(mem_fd, buffer, size, start);
                if (nread < 0) {
                    perror("pread");
                    free(buffer);
                    continue;
                }

                char outfile[256];
                snprintf(outfile, sizeof(outfile), "stack_%d_%d.bin", pid, tid);
                FILE *out = fopen(outfile, "wb");
                if (!out) {
                    perror("fopen output");
                    free(buffer);
                    continue;
                }

                fwrite(buffer, 1, nread, out);
                fclose(out);
                printf("Stack dumped to %s\n", outfile);

                free(buffer);
            }
        }
    }

    close(mem_fd);
    fclose(maps);
}

int is_number(const char *str) {
    while (*str) {
        if (!isdigit(*str++))
            return 0;
    }
    return 1;
}

void dump_all_stacks(pid_t pid) {
    char task_path[256];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);
    DIR *dir = opendir(task_path);
    if (!dir) {
        perror("opendir task");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_type == DT_DIR && is_number(entry->d_name)) {
            pid_t tid = atoi(entry->d_name);
            dump_stack(pid, tid);
        }
    }

    closedir(dir);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    dump_all_stacks(pid);
    return 0;
}
