// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2021 Tony Ambardar

// When dnsmasq loads large domain blocklists and then forks children to
// handle DNS requests over TCP, this can trigger the OOM killer on Linux,
// followed by the system degrading or crashing.
//
// Root cause is because these static blocklists are created in PRIVATE
// ANONYMOUS memory by default, and when forking children Linux accounts
// for each instance of blocklist memory. One solution for sharing this
// blocklist with children is using SHARED ANONYMOUS memory, for which
// Linux accounts only the single instance. For futher details see:
// https://www.kernel.org/doc/html/v5.4/vm/overcommit-accounting.html
//
// This program emulates dnsmasq execution loading large blocklists and
// then forking children to handle TCP DNS requests. At each step, it
// prints committed memory from /proc/meminfo, tracking the risk of OOM.
// Option "--private" reproduces normal dnsmasq behaviour and can easily
// trigger OOM on small memory systems (e.g. 128MB). Option "--shared"
// demonstrates SHARED ANONYMOUS memory usage and works on small systems.
//
// How to Use
// ==========
// $ gcc -Wall -Werror -o oom_alloc oom_alloc.c
// $ ./oom_alloc
// ./oom_alloc [ --shared | --private ]

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define ALLOC_MB 64   // allocated memory in the parent for blocklists
#define NUM_CHLD 16   // children forked, each with a blocklist instance

static void
print_mem_commit(const char *msg)
{
    const char *memstr = "Committed_AS:";
    char buf[100];
    FILE *fp = fopen("/proc/meminfo", "r");

    if (!fp)
        handle_error("file open");

    while (fgets(buf, sizeof(buf), fp))
        if (strncmp(buf, memstr, strlen(memstr)) == 0)
            fprintf(stdout, "%s    (%s)\n", strtok(buf, "\n"), msg);

    fclose (fp);
}

static void
usage(char *argv[])
{
    fprintf(stderr, "%s [ --shared | --private ]\n", argv[0]);
    exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
    const size_t length = ALLOC_MB*(1024*1024);
    int wstatus;
    pid_t chld;
    int shared;
    void *addr;
    int *p, i;

    if (argc != 2)
        usage(argv);

    if ((strcmp(argv[1], "--shared") == 0))
        shared = 1;
    else if ((strcmp(argv[1], "--private") == 0))
        shared = 0;
    else
        usage(argv);

    fprintf(stdout, "Test dnsmasq OOM: memory allocation and forking\n");
    fprintf(stdout, "(allocate %u MB %s anonymous, fork %u processes)\n",
            ALLOC_MB, (shared ? "shared" : "private") ,NUM_CHLD);

    print_mem_commit("initial state");

    addr = mmap(NULL, length, PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | (shared ? MAP_SHARED : MAP_PRIVATE), -1, 0);
    if (addr == MAP_FAILED)
        handle_error("mmap");
    print_mem_commit("parent mem allocated");

    for (p = addr, i = 0; i < (length / sizeof(*p)); p++, i++)
        *p = i;
    print_mem_commit("parent mem initialized");

    if (mprotect(addr, length, PROT_READ) == -1)
        handle_error("mprotect");
    print_mem_commit("parent mem set-readonly");

    for (i = 0; i < NUM_CHLD; i++) {
        if ((chld = fork()) == 0) {
            sleep(3);
            exit(EXIT_SUCCESS);
        }
        if (chld == -1)
            handle_error("fork");
    }
    print_mem_commit("parent forked children");

    for (i = 0; i < NUM_CHLD; i++) {
        if (wait(&wstatus) == -1)
            handle_error("wait");
    }
    print_mem_commit("parent reaped children");

    munmap(addr, length);
    print_mem_commit("parent mem unmapped");

    exit(EXIT_SUCCESS);
}
