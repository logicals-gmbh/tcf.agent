/*******************************************************************************
 * Copyright (c) 2007, 2012 Wind River Systems, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 * You may elect to redistribute this code under either of these licenses.
 *
 * Contributors:
 *     Wind River Systems - initial API and implementation
 *******************************************************************************/

/*
 * This module contains definitions of target CPU registers and stack frames.
 */

#ifndef D_cpudefs
#define D_cpudefs

#include <tcf/config.h>

typedef struct Context Context;
typedef struct ContextBreakpoint ContextBreakpoint;

/* Type to represent byte address inside context memory */
#if ENABLE_ContextProxy
typedef uint64_t ContextAddress;
#else
typedef uintptr_t ContextAddress;
#endif

#if ENABLE_DebugContext

#define REGNUM_DWARF    1
#define REGNUM_EH_FRAME 2

typedef struct RegisterData RegisterData;

typedef struct RegisterDefinition RegisterDefinition;
typedef struct NamedRegisterValue NamedRegisterValue;

struct NamedRegisterValue {
    uint8_t * value;
    const char * name;
    const char * description;
};

struct RegisterDefinition {
    const char *    name;          /* pointer to register name */
    size_t          offset;        /* offset to entry in REG_SET */
    size_t          size;          /* register size in bytes */
    int16_t         dwarf_id;      /* ID of the register in DWARF sections, or -1 */
    int16_t         eh_frame_id;   /* ID of the register in .eh_frame section, or -1 */
    uint8_t         big_endian;    /* 0 - little endian, 1 -  big endian */
    uint8_t         fp_value;      /* true if the register value is a floating-point value */
    uint8_t         no_read;       /* true if context value can not be read */
    uint8_t         no_write;      /* true if context value can not be written */
    uint8_t         read_once;     /* true if reading the context (register) destroys its current value */
    uint8_t         write_once;    /* true if register value can not be overwritten - every write counts */
    uint8_t         side_effects;  /* true if writing the context can change values of other registers */
    uint8_t         volatile_value;/* true if the register value can change even when target is stopped */
    uint8_t         left_to_right; /* true if the lowest numbered bit should be shown to user as the left-most bit */
    int             first_bit;     /* bit numbering base (0 or 1) to use when showing bits to user */
    int *           bits;          /* if context is a bit field, contains the field bit numbers in the parent register definition, -1 marks end of the list */
    RegisterDefinition * parent;   /* parent register definition, NULL for top level definitions */
    NamedRegisterValue ** values;  /* predefined names (mnemonics) for some of register values */
    ContextAddress  memory_address;/* the address of a memory mapped register */
    const char *    memory_context;/* the context ID of a memory context in which a memory mapped register is located */
    const char *    role;          /* the role the register plays in a program execution */
    const char *    description;   /* the description of the register */
};

typedef struct RegisterIdScope {
    uint16_t machine;
    uint8_t os_abi;
    uint8_t fp_abi;
    uint8_t elf64;
    uint8_t big_endian;
    uint8_t id_type;
} RegisterIdScope;

/* Location expression command codes */
#define SFT_CMD_NUMBER          1
#define SFT_CMD_RD_REG          2
#define SFT_CMD_FP              3
#define SFT_CMD_RD_MEM          4
#define SFT_CMD_ADD             5
#define SFT_CMD_SUB             6
#define SFT_CMD_MUL             7
#define SFT_CMD_DIV             8
#define SFT_CMD_AND             9
#define SFT_CMD_OR             10
#define SFT_CMD_XOR            11
#define SFT_CMD_NEG            12
#define SFT_CMD_GE             13
#define SFT_CMD_GT             14
#define SFT_CMD_LE             15
#define SFT_CMD_LT             16
#define SFT_CMD_SHL            17
#define SFT_CMD_SHR            18
#define SFT_CMD_ARG            19
#define SFT_CMD_LOCATION       20 /* A DWARF location expression */
#define SFT_CMD_FCALL          21
#define SFT_CMD_WR_REG         22
#define SFT_CMD_WR_MEM         23
#define SFT_CMD_PIECE          24

#define SFT_CMD_REGISTER        2 /* Deprecated, use SFT_CMD_RD_REG */
#define SFT_CMD_DEREF           4 /* Deprecated, use SFT_CMD_RD_MEM */

typedef struct LocationExpressionCommand LocationExpressionCommand;

typedef struct LocationPiece {
    ContextAddress addr;
    RegisterDefinition * reg;
    void * value;
    size_t size;
    unsigned bit_offs;
    unsigned bit_size;
} LocationPiece;

typedef struct LocationExpressionState {
    /* Evaluation context */
    Context * ctx;
    struct StackFrame * stack_frame;
    RegisterIdScope reg_id_scope;
    size_t addr_size;
    uint64_t * args;
    unsigned args_cnt;

    /* Code to execute */
    uint8_t * code;
    size_t code_pos;
    size_t code_len;

    /* Client callback */
    void (*client_op)(uint8_t op);

    /* Result */
    LocationExpressionCommand * sft_cmd;
    LocationPiece * pieces;
    unsigned pieces_cnt;
    unsigned pieces_max;

    /* Evaluation stack */
    unsigned stk_pos;
    unsigned stk_max;
    uint64_t * stk;
} LocationExpressionState;

typedef int LocationExpressionCallback(LocationExpressionState *);

/* Location expression command */
struct LocationExpressionCommand {
    int cmd;
    union {
        int64_t num;
        RegisterDefinition * reg;
        struct {
            size_t size;
            int big_endian;
        } deref; /* Deprecated, use .mem */
        struct {
            size_t size;
            int big_endian;
        } mem;
        struct {
            LocationExpressionCallback * func;
            RegisterIdScope reg_id_scope;
            uint8_t * code_addr;
            size_t code_size;
            size_t addr_size;
        } loc;
        struct {
            void * value;
            RegisterDefinition * reg;
            unsigned bit_offs;
            unsigned bit_size;
        } piece;
        unsigned arg_no;
    } args;
};

#define STACK_BOTTOM_FRAME  0
#define STACK_NO_FRAME      (-1)
#define STACK_TOP_FRAME     (-2)

typedef struct StackFrame {
    int is_top_frame;
    int is_walked;          /* Data collected by: 0 - crawl, 1 - walk */
    int has_reg_data;
    Context * ctx;
    ContextAddress fp;      /* frame address */
    RegisterData * regs;    /* register values */
} StackFrame;

/* Return array of CPU register definitions. Last item in the array has name == NULL */
extern RegisterDefinition * get_reg_definitions(Context * ctx);

/* Search register definition for given register ID, return NULL if not found */
extern RegisterDefinition * get_reg_by_id(Context * ctx, unsigned id, RegisterIdScope * scope);

/* Return register definition of instruction pointer */
extern RegisterDefinition * get_PC_definition(Context * ctx);

/* Read register value from stack frame data, return 0 on success, return -1 and set errno if register is not available  */
extern int read_reg_value(StackFrame * frame, RegisterDefinition * reg_def, uint64_t * value);

/* Write register value into stack frame data, return 0 on success, return -1 and set errno if register is not available  */
extern int write_reg_value(StackFrame * frame, RegisterDefinition * reg_def, uint64_t value);

/* Read register bytes from stack frame data, return 0 on success, return -1 and set errno if register is not available  */
extern int read_reg_bytes(StackFrame * frame, RegisterDefinition * reg_def, unsigned offs, unsigned size, uint8_t * buf);

/* Write register bytes into stack frame data, return 0 on success, return -1 and set errno if register is not available  */
extern int write_reg_bytes(StackFrame * frame, RegisterDefinition * reg_def, unsigned offs, unsigned size, uint8_t * buf);

/* Get instruction pointer (PC) value */
extern ContextAddress get_regs_PC(Context * ctx);

/* Set instruction pointer (PC) value */
extern void set_regs_PC(Context * ctx, ContextAddress y);

/* Get TCF ID of a stack frame */
extern const char * frame2id(Context * ctx, int frame);

/* Get stack frame for TCF ID */
extern int id2frame(const char * id, Context ** ctx, int * frame);

/* Get TCF ID of a register */
extern const char * register2id(Context * ctx, int frame, RegisterDefinition * reg);

/* Get register for TCF ID */
extern int id2register(const char * id, Context ** ctx, int * frame, RegisterDefinition ** reg_def);

/* Get breakpoint instruction code and size */
extern uint8_t * get_break_instruction(Context * ctx, size_t * size);

/*
 * Retrieve stack frame information by examining stack data in memory.
 *
 * "frame" is current frame info, it should have frame->regs and frame->mask filled with
 * proper values before this function is called.
 *
 * "down" is next frame - moving from stack top to the bottom.
 *
 * The function uses register values in current frame to calculate frame address "frame->fp",
 * and calculate register values in the next frame.
 */
extern int crawl_stack_frame(StackFrame * frame, StackFrame * down);

/* Execute location expression. Throw an exception if error. */
extern LocationExpressionState * evaluate_location_expression(
            Context * ctx, StackFrame * frame,
            LocationExpressionCommand * cmds, unsigned cmds_cnt,
            uint64_t * args, unsigned args_cnt);

extern void read_location_peices(
            Context * ctx, StackFrame * frame,
            LocationPiece * pieces, unsigned pieces_cnt, int big_endian,
            void ** value, size_t * size);

extern void write_location_peices(
            Context * ctx, StackFrame * frame,
            LocationPiece * pieces, unsigned pieces_cnt, int big_endian,
            void * value, size_t size);

/*** CPU hardware breakpoints API ***/

/* Get supported memory access modes */
extern int cpu_bp_get_capabilities(Context * ctx);

/* Plant hardware breakpoint */
extern int cpu_bp_plant(ContextBreakpoint * bp);

/* Remove hardware breakpoint */
extern int cpu_bp_remove(ContextBreakpoint * bp);

/* Setup breakpoint registers for a context that is about to resume */
extern int cpu_bp_on_resume(Context * ctx, int * single_step);

/* Chcek breakpoint registers for a context that has stopped */
extern int cpu_bp_on_suspend(Context * ctx, int * triggered);


extern void ini_cpudefs(void);

#endif /* ENABLE_DebugContext */

#endif /* D_cpudefs */
