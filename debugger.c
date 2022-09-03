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
typedef struct breakpoint breakpoint_t;

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
typedef struct reg_descriptor reg_descriptor_t;

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
void continue_program();
void wait_for_signal(int *);
int strs_are_equal(char *, char *);
void enable_breakpoint(breakpoint_t *);
void disable_breakpoint(breakpoint_t *);
// uint64_t *get_register_address(char *, struct user_regs_struct *);
uint64_t read_memory(uint64_t);
void write_memory(uint64_t, uint64_t);
void step_over();
// const reg_descriptor_t *get_register_by_name(char *);
// const reg_descriptor_t *get_register_by_dwarf_number(int);
uint64_t get_pc();
void set_pc(uint64_t);

struct debugee *child;

struct breakpoint *breakpt;
// breakpoint_t breakpts[10];

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
  // free(breakpts);
  return 0;
}

uint64_t read_memory(uint64_t addr)
{
  uint64_t data = ptrace(PTRACE_PEEKDATA, child->pid, addr, NULL);
  return data;
}

uint64_t get_pc()
{
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, child->pid, NULL, &regs); // Hace una copia en &regs
  return (uint64_t)regs.rip;
}

void set_pc(uint64_t pc)
{
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, child->pid, NULL, &regs); // Hace una copia en &regs
  regs.rip = pc;
  ptrace(PTRACE_SETREGS, child->pid, NULL, &regs); // Se actualiza &regs
}

void write_memory(uint64_t addr, uint64_t value)
{
  ptrace(PTRACE_POKEDATA, child->pid, addr, value);
}

void step_over()
{
  uint64_t last_instruction = get_pc() - 1;
  if (breakpt->active)
  {
    if (last_instruction == breakpt->addr)
    {
      set_pc(last_instruction);
      disable_breakpoint(breakpt);
      ptrace(PTRACE_SINGLESTEP, child->pid, NULL, NULL);
      int status;
      wait_for_signal(&status);
      enable_breakpoint(breakpt);
    }
  }
}

void next_line()
{
  // uint64_t last_instruction = get_pc() - 1;
  // set_pc(last_instruction);
  // ptrace(PTRACE_SINGLESTEP, child->pid, NULL, NULL);
  // int status;
  // wait_for_signal(&status);
}

int strs_are_equal(char *str1, char *str2)
{
  int result = strcmp(str1, str2);
  if (result == 0)
  {
    return 1;
  }
  return 0;
}

void wait_for_signal(int *wait_status)
{
  int options = 0;
  waitpid(child->pid, wait_status, options);
}

void continue_program()
{
  step_over();
  ptrace(PTRACE_CONT, child->pid, NULL, NULL);
  int status;
  wait_for_signal(&status);
}

void enable_breakpoint(breakpoint_t *bp)
{
  uint64_t data = ptrace(PTRACE_PEEKDATA, child->pid, bp->addr, NULL);
  bp->prev_opcode = (uint64_t)(data & 0xff);
  uint64_t int3 = 0xcc;
  uint64_t data_with_int3 = ((data & ~0xff) | int3);
  ptrace(PTRACE_POKEDATA, child->pid, bp->addr, data_with_int3);
  bp->active = 1;
}

void disable_breakpoint(breakpoint_t *bp)
{
  uint64_t data = ptrace(PTRACE_PEEKDATA, child->pid, bp->addr, NULL);
  uint64_t restored_data = ((data & ~0xff) | bp->prev_opcode);
  ptrace(PTRACE_POKEDATA, child->pid, bp->addr, restored_data);
  bp->active = 0;
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

  if (strs_are_equal(operation, "continue"))
  {
    continue_program();
  }
  else if (strs_are_equal(operation, "next"))
  {
    next_line();
  }
  else if (strs_are_equal(operation, "break"))
  {
    breakpt->addr = (uint64_t)strtol(inputs[1], NULL, 0);
    enable_breakpoint(breakpt);
  }
  else if (strs_are_equal(operation, "register"))
  {
    struct user_regs_struct regs;
    uint64_t *rip_register_address = (uint64_t *)&(regs.rip);
    ptrace(PTRACE_GETREGS, child->pid, NULL, &regs);
    if (strs_are_equal(inputs[1], "read"))
    {
      printf("rip value: %ld", *rip_register_address);
    }
    else if (strs_are_equal(inputs[1], "write"))
    {
      *rip_register_address = (uint64_t)strtol(inputs[3], NULL, 0);
      ptrace(PTRACE_SETREGS, child->pid, NULL, &regs); // Se actualiza &regs
    }
  } /*else if(strs_are_equal(operation, "memory")){
        if(strs_are_equal(inputs[1], "read")){
            printf("Value in memory: %ld", read_memory((uint64_t)strtol(inputs[2], NULL, 0)));
        }
        else if(strs_are_equal(inputs[1], "write")){
            write_memory((uint64_t)strtol(inputs[2], NULL, 0), (uint64_t)strtol(inputs[3], NULL, 0));
        }
    }*/
  else
  {
    printf("Bad command");
  }

  // At this point you must to implement all the logic to manage the inputs of the program:
  // continue -> To continue the execution of the program
  // step_over -> To go step by step
  // register write/read <reg_name> <value>(when write format 0xVALUE) -> To read/write the value of a register (see the global variable g_register_descriptors)
  // break <0xVALUE> (Hexadecimal) -> To put a breakpoint in an adress

  // The following lines show a basic example of how to use the PTRACE API

  // Read the registers
  // struct user_regs_struct regs;
  // uint64_t *register_address;
  // ptrace(PTRACE_GETREGS, child->pid, NULL, &regs);

  // // Write the registers -> If you want to change a register, you must to read them first using the previous call, modify the struct user_regs_struct
  // //(the register that you want to change) and then use the following call
  // ptrace(PTRACE_SETREGS, child->pid, NULL, &regs);

  // // If you want to enable a breakpoint (in a provided adress, for example 0x555555554655), you must to use the following CALL
  // breakpt->addr = ((uint64_t)strtol("0x555555554655", NULL, 0));
  // uint64_t data = ptrace(PTRACE_PEEKDATA, child->pid, breakpt->addr, NULL);
  // breakpt->prev_opcode = (uint8_t)(data & 0xff);
  // uint64_t int3 = 0xcc;
  // uint64_t data_with_int3 = ((data & ~0xff) | int3);
  // ptrace(PTRACE_POKEDATA, child->pid, breakpt->addr, data_with_int3);
  // breakpt->active = 1;

  // // To disable a breakpoint
  // data = ptrace(PTRACE_PEEKDATA, child->pid, breakpt->addr, NULL);
  // uint64_t restored_data = ((data & ~0xff) | breakpt->prev_opcode);
  // ptrace(PTRACE_POKEDATA, child->pid, breakpt->addr, restored_data);
  // breakpt->active = 0;

  // // To execute a singe step
  // ptrace(PTRACE_SINGLESTEP, child->pid, NULL, NULL);

  // // To read the value in a memory adress
  // uint64_t value_in_memory = (uint64_t)ptrace(PTRACE_PEEKDATA, child->pid, (uint64_t)strtol("0x555555554655", NULL, 0), NULL);

  // // To write a value in an adress
  // ptrace(PTRACE_POKEDATA, child->pid, (uint64_t)strtol("0x555555554655", NULL, 0), (uint64_t)strtol("0x555555554655", NULL, 0));

  // // If you want to continue with the execution of the debugee program
  // ptrace(PTRACE_CONT, child->pid, NULL, NULL);
  // int status;
  // int options = 0;
  // waitpid(child->pid, &status, options);
}
