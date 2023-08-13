// #include "decode.h"
// #include "trap.h"

/*exception*/
if (!IS_CAP(insn_rs1) || !IS_DATA(insn_rs2))
	throw trap_capstone_unexpected_operand_type(insn.bits());
if (!VALID_CAP(insn_rs1))
	throw trap_capstone_invalid_capability(insn.bits());
cap_type_t tmp_type = READ_CAP(insn_rs1).type;
if (tmp_type != CAP_TYPE_LINEAR && tmp_type != CAP_TYPE_NONLINEAR)
	throw trap_capstone_unexpected_cap_type(insn.bits());
if (RS2 <= READ_CAP(insn_rs1).base || RS2 >= READ_CAP(insn_rs1).end)
	throw trap_capstone_illegal_operand_value(insn.bits());
/*split the capability*/
if (insn_rs1 != insn_rd) {
	uint64_t tmp_val = RS2;
	/*rs1 -> rd*/
	// update rc
  if (IS_CAP(insn_rd)) UPDATE_RC_DOWN(READ_CAP_NODE(insn_rd));
	WRITE_CAP_DUMB(insn_rd, READ_CAP(insn_rs1));
	/*adjust rs1*/
	READ_CAP(insn_rs1).end = tmp_val;
	READ_CAP(insn_rs1).cursor = READ_CAP(insn_rs1).base;
	/*adjust rs2*/
	// allocate new node
	rev_node_id_t split_node_id = SPLIT_RT(READ_CAP_NODE(insn_rs1));
	assert(split_node_id != REV_NODE_ID_INVALID); // crush if no more node
	READ_CAP(insn_rd).node_id = split_node_id;
	READ_CAP(insn_rd).base = tmp_val;
	READ_CAP(insn_rd).cursor = tmp_val;
}
