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

struct reg_descriptor
{
    int dwarf_r;
    char *name;
};

const int n_registers = 27;

const struct reg_descriptor g_register_descriptors[] = {
    {0, "r15"},
    {1, "r14"},
    {2, "r13"},
    {3, "r12"},
    {4, "rbp"},
    {5, "rbx"},
    {6, "r11"},
    {7, "r10"},
    {8, "r9"},
    {9, "r8"},
    {10, "rax"},
    {11, "rcx"},
    {12, "rdx"},
    {13, "rsi"},
    {14, "rdi"},
    {15, "orig_rax"},
    {16, "rip"},
    {17, "cs"},
    {18, "eflags"},
    {19, "rsp"},
    {20, "ss"},
    {21, "fs_base"},
    {22, "gs_base"},
    {23, "ds"},
    {24, "es"},
    {25, "fs"},
    {26, "gs"},
};

void handle_command(char *);

struct debugee *child;
struct breakpoint *breakpt;

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
        int status;
        int options = 0;
        waitpid(child->pid, &status, options);
        char *line = NULL;
        while ((line = linenoise("minidbg> ")) != NULL)
        {
            handle_command(line);
            linenoiseHistoryAdd(line);
            linenoiseFree(line);
        }
    }

    free(child);
    free(breakpt);
    return 0;
}

void handle_command(char *line)
{
    // At this point you must to implement all the logic to manage the inputs of the program:
    // continue -> To continue the execution of the program
    // next -> To go step by step
    // register write/read <reg_name> <value>(when write format 0xVALUE) -> To read/write the value of a register (see the global variable g_register_descriptors)
    // break <0xVALUE> (Hexadecimal) -> To put a breakpoint in an adress

    // The following lines show a basic example of how to use the PTRACE API

    // Read the registers
    struct user_regs_struct regs;
    uint64_t *register_address;
    ptrace(PTRACE_GETREGS, child->pid, NULL, &regs);

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
        printf("continue\n");
    }
    else if (strcmp(operation, "next") == 0)
    {
        printf("next\n");

    }
    else if (strcmp(operation, "break") == 0)
    {
        printf("break\n");

    }
    else if (strcmp(operation, "register") == 0)
    {
        printf("register\n");

    }
    else
    {
        printf("Invalid Input\n");
    }


    // //Write the registers -> If you want to change a register, you must to read them first using the previous call, modify the struct user_regs_struct
    // //(the register that you want to change) and then use the following call
    // ptrace(PTRACE_SETREGS, child->pid, NULL, &regs);

    // //If you want to enable a breakpoint (in a provided adress, for example 0x555555554655), you must to use the following CALL
    // breakpt->addr =  ((uint64_t)strtol("0x555555554655", NULL, 0));
    // uint64_t data = ptrace(PTRACE_PEEKDATA, child->pid, breakpt->addr, NULL);
    // breakpt->prev_opcode = (uint8_t)(data & 0xff);
    // uint64_t int3 = 0xcc;
    // uint64_t data_with_int3 = ((data & ~0xff) | int3);
    // ptrace(PTRACE_POKEDATA, child->pid, breakpt->addr, data_with_int3);
    // breakpt->active = 1;

    // //To disable a breakpoint
    // data = ptrace(PTRACE_PEEKDATA, child->pid, breakpt->addr, NULL);
    // uint64_t restored_data = ((data & ~0xff) | breakpt->prev_opcode);
    // ptrace(PTRACE_POKEDATA, child->pid, breakpt->addr, restored_data);
    // breakpt->active = 0;

    // //To execute a singe step
    // ptrace(PTRACE_SINGLESTEP, child->pid, NULL, NULL);

    // //To read the value in a memory adress
    // uint64_t value_in_memory = (uint64_t)ptrace(PTRACE_PEEKDATA, child->pid, (uint64_t)strtol("0x555555554655", NULL, 0), NULL);

    // //To write a value in an adress
    // ptrace(PTRACE_POKEDATA, child->pid, (uint64_t)strtol("0x555555554655", NULL, 0), (uint64_t)strtol("0x555555554655", NULL, 0));

    // If you want to continue with the execution of the debugee program
//     ptrace(PTRACE_CONT, child->pid, NULL, NULL);
//     int status;
//     int options = 0;
//     waitpid(child->pid, &status, options);
}
