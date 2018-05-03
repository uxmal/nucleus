#ifndef NUCLEUS_INSN_H
#define NUCLEUS_INSN_H

#include <stdio.h>
#include <stdint.h>

#include <capstone/capstone.h>

#include <string>
#include <vector>

#include "edge.h"

class Operand {
public:
  enum OperandType {
    OP_TYPE_NONE = 0,
    OP_TYPE_REG  = 1,
    OP_TYPE_IMM  = 2,
    OP_TYPE_MEM  = 3,
    OP_TYPE_FP   = 4
  };

  union AArch64Value {
    AArch64Value() { reg = ARM64_REG_INVALID; imm = 0; fp = 0; mem.base = 0; mem.index = 0; mem.disp = 0; }
    AArch64Value(const AArch64Value &v) { mem.base = v.mem.base;
      mem.index = v.mem.index; mem.disp = v.mem.disp; }

    arm64_reg    reg;
    int32_t      imm;
    double       fp;
    arm64_op_mem mem;
  };

  union ARMValue {
    ARMValue() { reg = ARM_REG_INVALID; imm = 0; fp = 0; mem.base = 0; mem.index = 0; mem.scale = 0; mem.disp = 0; }
    ARMValue(const ARMValue &v) { mem.base = v.mem.base; mem.index = v.mem.index;
      mem.scale = v.mem.scale; mem.disp = v.mem.disp; }

    arm_reg    reg;
    int32_t    imm;
    double     fp;
    arm_op_mem mem;
  };

  union MIPSValue {
    MIPSValue() { reg = MIPS_REG_INVALID; imm = 0; fp = 0; mem.base = 0; mem.disp = 0; }
    MIPSValue(const MIPSValue &v) { mem.base = v.mem.base; mem.disp = v.mem.disp; }

    mips_reg    reg;
    int32_t     imm;
    double      fp;
    mips_op_mem mem;
  };

  union PPCValue {
    PPCValue() { reg = PPC_REG_INVALID; imm = 0; mem.base = 0; mem.disp = 0; }
    PPCValue(const PPCValue &v) { mem.base = v.mem.base; mem.disp = v.mem.disp; }

    ppc_reg    reg;
    int32_t    imm;
    ppc_op_mem mem;
  };

  union X86Value {
    X86Value() { reg = X86_REG_INVALID; imm = 0; fp = 0; mem.segment = 0; mem.base = 0; mem.index = 0; mem.scale = 0; mem.disp = 0; }
    X86Value(const X86Value &v) { mem.segment = v.mem.segment; mem.base = v.mem.base;
      mem.index = v.mem.index; mem.scale = v.mem.scale;
      mem.disp = v.mem.disp; }

    x86_reg    reg;
    int64_t    imm;
    double     fp;
    x86_op_mem mem;
  };

  Operand() : type(OP_TYPE_NONE), size(0), x86_value() {}
  Operand(const Operand &op) : type(op.type), size(op.size), x86_value(op.x86_value) {}

  uint8_t type;
  uint8_t size;

  union {
    AArch64Value aarch64_value; /* Only set if the arch is aarch64 */
    ARMValue arm_value; /* Only set if the arch is arm */
    MIPSValue mips_value; /* Only set if the arch is mips */
    PPCValue ppc_value; /* Only set if the arch is ppc */
    X86Value x86_value; /* Only set if the arch is x86 */
  };
};

class Instruction {
public:
  enum InstructionFlags {
    INS_FLAG_CFLOW    = 0x001,
    INS_FLAG_COND     = 0x002,
    INS_FLAG_INDIRECT = 0x004,
    INS_FLAG_JMP      = 0x008,
    INS_FLAG_CALL     = 0x010,
    INS_FLAG_RET      = 0x020,
    INS_FLAG_NOP      = 0x040
  };

  Instruction() : id(0), start(0), size(0), addr_size(0), target(0), flags(0), invalid(false), privileged(false), trap(false) {}
  Instruction(const Instruction &i) : id(i.id), start(i.start), size(i.size), addr_size(i.addr_size), target(i.target), flags(i.flags),
                                      mnem(i.mnem), op_str(i.op_str), operands(i.operands), invalid(i.invalid), privileged(i.privileged), trap(i.trap) {}

  void           print     (FILE *out);
  Edge::EdgeType edge_type ();

  unsigned int         id;
  uint64_t             start;
  uint8_t              size;
  uint8_t              addr_size;
  uint64_t             target;
  unsigned short       flags;
  std::string          mnem;
  std::string          op_str;
  std::vector<Operand> operands;
  bool                 invalid;
  bool                 privileged;
  bool                 trap;
};

class X86Instruction : public Instruction {
public:
  static const uint8_t MAX_LEN = 16;

  X86Instruction() : Instruction() {}
  X86Instruction(const X86Instruction &i) : Instruction(i) {}
};

#endif /* NUCLEUS_INSN_H */

