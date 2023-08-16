// #include "decode.h"
// #include "trap.h"

/*exception*/
if (IS_NORMAL_WORLD())
	throw trap_capstone_illegal_instruction(insn.bits());
if (!IS_CAP(insn_rs1))
	throw trap_capstone_unexpected_operand_type(insn.bits());
/*unconditional jump and link*/
cap64_t tmp_cap = READ_CAP(insn_rs1);
/*pc -> rd*/
STATE.cap_pc.cursor = npc;
WRITE_CAP(insn_rd, STATE.cap_pc);
/*cap -> pc*/
// disable cap_pc cursor update in insn_template.cc
update_cursor = false;
tmp_cap.cursor += insn_i_imm;
STATE.cap_pc = tmp_cap;
// pc is replaced by npc outside this function
set_pc(tmp_cap.cursor);
/*reset rs1*/
if (insn_rs1 != insn_rd) {
	if (IS_LINEAR(insn_rs1)) {
		RESET_REG(insn_rs1);
	}
	else {
		UPDATE_RC_UP(READ_CAP_NODE(insn_rs1));
	}
}
