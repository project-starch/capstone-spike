// #include "decode.h"
// #include "trap.h"

/*exception*/
if (!IS_CAP(insn_rs1))
  throw trap_capstone_unexpected_operand_type(insn.bits());
if (!VALID_CAP(insn_rs1))
  throw trap_capstone_invalid_capability(insn.bits());
if (READ_CAP(insn_rs1).type != CAP_TYPE_LINEAR)
  throw trap_capstone_unexpected_cap_type(insn.bits());
/*mint a revocation capability*/
/*rs1 -> rd*/
if (IS_CAP(insn_rd)) UPDATE_RC_DOWN(READ_CAP_NODE(insn_rd));
WRITE_CAP_DUMB(insn_rd, READ_CAP(insn_rs1));
/*update rs1 capability node_id*/
rev_node_id_t mrev_node_id = ALLOCATE_NODE(READ_CAP_NODE(insn_rs1));
if (mrev_node_id == REV_NODE_ID_INVALID)
  throw trap_capstone_insufficient_system_resources(insn.bits());
READ_CAP(insn_rs1).node_id = mrev_node_id;
/*update rd capability type*/
if (NOT_ZERO_REG(insn_rd)) {
  READ_CAP(insn_rd).type = CAP_TYPE_REVOCATION;
}
