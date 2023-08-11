// #include "decode.h"
// #include "trap.h"

/*exception*/
if (!IS_CAP(insn_rs1))
  throw trap_capstone_unexpected_operand_type(insn.bits());
/*move capability x[rd] to x[rs1]*/
MOVC(insn_rd, insn_rs1);
