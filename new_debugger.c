#include <stdio.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/personality.h>
#include "linenoise.h"

struct breakpoint
{
    uint64_t addr;
    uint8_t prev_opcode;
    uint8_t active;
};

struct debugee
{
    char *name;
    pid_t pid;
};

void handle_command(char *);
void continue_program();
void next_step();
void enable_breakpoint(int bpIdx, long addr);
void disable_breakpoint(int bpIdx);
void jump_to_addr(char *addr);
void print_help();

void step_by_step();

struct debugee *child;
struct breakpoint *breakpt;
struct breakpoint *breakpts[10];

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Program name not specified");
        return -1;
    }
    child = (struct debugee *)malloc(sizeof(struct debugee));
    breakpt = (struct breakpoint *)malloc(sizeof(struct breakpoint));
    breakpt->active = 0;
    for (int i = 0; i < 10; i++)
    {
        breakpts[i] = (struct breakpoint *)malloc(sizeof(struct breakpoint));
        breakpts[i]->active = 0;
    }

    child->name = argv[1];
    child->pid = fork();

    if (child->pid == 0)
    {
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(child->name, child->name, NULL);
    }
    else if (child->pid >= 1)
    {
        print_help();

        struct user_regs_struct regs;
        uint64_t *rip_register_address = (uint64_t *)&(regs.rip);

        int status;
        int options = 0;
        waitpid(child->pid, &status, options);
        char *line = NULL;
        while ((line = linenoise("minidbg> ")) != NULL)
        {
            handle_command(line);
            linenoiseHistoryAdd(line);
            linenoiseFree(line);

            ptrace(PTRACE_GETREGS, child->pid, NULL, &regs);
            printf("\nPC: %lu\n", *rip_register_address);
        }
    }

    free(child);
    free(breakpt);
    return 0;
}

void print_help()
{
    printf("usage:\n");
    printf("\tcontinue \t\n");
    printf("\tbreak    \t<brkpt idx> <instruction addr>\n");
    printf("\tunbreak  \t<brkpt idx>\n");
    printf("\tjump     \t<instruction addr>\n");
    printf("\n");
    // printf("\tunbreak  \t<brkpt idx>\n");
}

void continue_program()
{
    // step_over(0);
    ptrace(PTRACE_CONT, child->pid, NULL, NULL);
    int status;
    int options = 0;
    waitpid(child->pid, &status, options);
}

void next_step()
{
    ptrace(PTRACE_SINGLESTEP, child->pid, NULL, NULL);
    int status;
    int options = 0;
    waitpid(child->pid, &status, options);
}

void step_by_step()
{
    int status;
    struct user_regs_struct regs;
    while (1)
    {
        ptrace(PTRACE_GETREGS, child->pid, NULL, &regs);
        printf("eip: %lu\n", (uint64_t)regs.rip);
        ptrace(PTRACE_SINGLESTEP, child->pid, NULL, NULL);
        waitpid(child->pid, &status, 0);
        if (WIFEXITED(status))
            break;
    }
    printf("end\n");
}

void enable_breakpoint(int bpIdx, long addr)
{
    if (bpIdx > 9)
    {
        printf("Breakpoint %d is not a valid breakpoint\n", bpIdx);
        return;
    }
    if (breakpts[bpIdx]->active == 1)
    {
        printf("Breakpoint %d is already occupied, use another one or free this one\n", bpIdx);
        // disable_breakpoint(bpIdx);
        return;
    }
    breakpts[bpIdx]->addr = addr;
    uint64_t data = ptrace(PTRACE_PEEKDATA, child->pid, breakpts[bpIdx]->addr, NULL);
    breakpts[bpIdx]->prev_opcode = (uint8_t)(data & 0xff);
    uint64_t int3 = 0xcc;
    uint64_t data_with_int3 = ((data & ~0xff) | int3);
    ptrace(PTRACE_POKEDATA, child->pid, breakpts[bpIdx]->addr, data_with_int3);
    breakpts[bpIdx]->active = 1;
}

void disable_breakpoint(int bpIdx)
{
    if (bpIdx > 9)
    {
        printf("Breakpoint %d is not a valid breakpoint\n", bpIdx);
        return;
    }
    if (breakpts[bpIdx]->active == 0)
    {
        printf("Breakpoint %d is already free\n", bpIdx);
        return;
    }
    uint64_t data = ptrace(PTRACE_PEEKDATA, child->pid, breakpts[bpIdx]->addr, NULL);
    uint64_t restored_data = ((data & ~0xff) | breakpts[bpIdx]->prev_opcode);
    ptrace(PTRACE_POKEDATA, child->pid, breakpts[bpIdx]->addr, restored_data);
    breakpts[bpIdx]->active = 0;
}

void jump_to_addr(char *addr)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child->pid, NULL, &regs);
    uint64_t *rip_register_address = (uint64_t *)&(regs.rip);
    *rip_register_address = (uint64_t)strtol(addr, NULL, 0);
    ptrace(PTRACE_SETREGS, child->pid, NULL, &regs);
}

void handle_command(char *line)
{
    char *inputs[5];
    int input_counter = 0;
    char *line_copy;
    line_copy = strdup(line);
    char *token = strtok(line_copy, " ");

    while (token != NULL)
    {
        inputs[input_counter] = strdup(token);
        token = strtok(NULL, " ");
        input_counter++;
        if (input_counter == 5)
        {
            printf("Something wrong");
        }
    }
    char *operation = inputs[0];

    if (strcmp(operation, "continue") == 0)
    {
        continue_program();
    }
    else if (strcmp(operation, "next") == 0)
    {
        step_by_step();
    }
    else if (strcmp(operation, "break") == 0)
    {
        enable_breakpoint(atoi(inputs[1]), (uint64_t)strtol(inputs[2], NULL, 0));
    }
    else if (strcmp(operation, "unbreak") == 0)
    {
        disable_breakpoint(atoi(inputs[1]));
    }
    else if (strcmp(operation, "jump") == 0)
    {
        jump_to_addr(inputs[1]);
    }
    else
    {
        printf("Invalid Input\n");
    }
}