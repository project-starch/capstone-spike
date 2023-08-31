// #include "decode.h"
// #include "trap.h"

/*exception*/
if (!IS_CAP(insn_rs1))
  throw trap_capstone_unexpected_operand_type(insn.bits());
cap_type_t tmp_type = READ_CAP(insn_rs1).type;
if (insn_i_imm == 2 && tmp_type == CAP_TYPE_UNINITIALIZED)
  throw trap_capstone_unexpected_cap_type(insn.bits());
if ((insn_i_imm == 4 || insn_i_imm == 5) && (tmp_type == CAP_TYPE_SEALED || tmp_type == CAP_TYPE_SEALEDRET || tmp_type == CAP_TYPE_EXIT))
  throw trap_capstone_unexpected_cap_type(insn.bits());
if (insn_i_imm == 6 && (tmp_type != CAP_TYPE_SEALED && tmp_type != CAP_TYPE_SEALEDRET))
  throw trap_capstone_unexpected_cap_type(insn.bits());
if (insn_i_imm == 7 && tmp_type != CAP_TYPE_SEALEDRET)
  throw trap_capstone_unexpected_cap_type(insn.bits());
/*field query*/
uint64_t tmp_value;
cap64_t tmp_cap = READ_CAP(insn_rs1);

switch (insn_i_imm) {
  case 0:
    tmp_value = VALID_CAP(insn_rs1)? 1 : 0;
    break;
  case 1:
    tmp_value = tmp_cap.type;
    break;
  case 2:
    tmp_value = tmp_cap.cursor;
    break;
  case 3:
    tmp_value = tmp_cap.base;
    break;
  case 4:
    tmp_value = tmp_cap.end;
    break;
  case 5:
    tmp_value = tmp_cap.perm;
    break;
  case 6:
    tmp_value = tmp_cap.async;
    break;
  case 7:
    tmp_value = tmp_cap.reg;
    break;
  default:
    tmp_value = 0;
}

WRITE_DATA(insn_rd, tmp_value);
