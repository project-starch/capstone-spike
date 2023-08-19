// #include "decode.h"
// #include "trap.h"

/*exception*/
if (IS_NORMAL_WORLD())
	throw trap_capstone_illegal_instruction(insn.bits());
if (!IS_CAP(insn_rd) || !IS_DATA(insn_rs1))
	throw trap_capstone_unexpected_operand_type(insn.bits());
/*conditional branch*/
if (RS1 != 0) {
	/*rd -> pc*/
	UPDATE_RC_DOWN(STATE.cap_pc.node_id);
	STATE.cap_pc = READ_CAP(insn_rd);
	/*update pc cursor*/
	STATE.cap_pc.cursor += insn_i_imm;
	set_pc(STATE.cap_pc.cursor);
	/*reset rd*/
	if (IS_LINEAR(insn_rd)) {
		RESET_REG(insn_rd);
	}
	else {
		UPDATE_RC_UP(READ_CAP_NODE(insn_rd));
	}
}
