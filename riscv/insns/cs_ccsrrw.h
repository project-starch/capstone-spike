#include "decode.h"
#include "trap.h"

uint64_t ccsr_num = insn_i_imm_zext;
/*exception*/
if (!IS_CAP(insn_rs1))
  throw trap_capstone_unexpected_operand_type(insn.bits());
if (CCSR_NUM_VALID(ccsr_num))
	throw trap_capstone_illegal_operand_value(insn.bits());
/*read/write CCSR*/
/*get read/write permission information*/
bool world_check = (CCSR(ccsr_num).ccsr_sw_only == IS_SECURE_WORLD());
bool read_check = CCSR(ccsr_num).ccsr_readable;
bool write_check = CCSR(ccsr_num).ccsr_writable;
/*additional read/write constraint*/
bool additional_read_check = true;
bool additional_write_check = true;
/*read*/
if (world_check && read_check && additional_read_check) {
	if (WRITE_CAP(insn_rd, CCSR(ccsr_num).cap)) {
		CCSR(ccsr_num).cap.reset();
	}
}
else {
	CLEAR_REG(insn_rd);
}
/*write*/
if (world_check && write_check && additional_write_check) {
	UPDATE_RC_DOWN(CCSR(ccsr_num).cap.node_id);
	CCSR(ccsr_num).cap = READ_CAP(insn_rs1);
	if (IS_LINEAR(insn_rs1)) {
		RESET_REG(insn_rs1);
	}
	else {
		UPDATE_RC_UP(READ_CAP_NODE(insn_rs1));
	}
}
