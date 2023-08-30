#include "decode.h"
#include "trap.h"
require_transcapstone;

/*exception*/
if (IS_SECURE_WORLD())
	throw trap_capstone_illegal_instruction(insn.bits());
if (!IS_CAP(insn_rs1))
	throw trap_capstone_unexpected_operand_type(insn.bits());
if (!VALID_CAP(insn_rs1))
	throw trap_capstone_invalid_capability(insn.bits());
if (READ_CAP(insn_rs1).type != CAP_TYPE_SEALED)
	throw trap_capstone_unexpected_cap_type(insn.bits());
/*synchronous*/
if (READ_CAP(insn_rs1).async == CAP_ASYNC_SYNC) {
	MOVC(cra_index, insn_rs1);
	/*normal_pc, normal_sp*/
	STATE.normal_pc = STATE.pc;
	if (IS_CAP(csp_index)) {
		// no rc update for csp
		STATE.normal_sp_cap.set_cap(READ_CAP(csp_index));
	}
	else {
		STATE.normal_sp_cap.set_data();
		STATE.normal_sp = READ_REG(csp_index);
	}
	/*pc*/
	uint64_t tmp_addr = READ_CAP(cra_index).base;
	uint128_t tmp_val;
	cap64_t tmp_cap;
	uint64_t tmp_data;
	if (GET_TAG(tmp_addr)) {
		SET_CAP_ACCESS();
		tmp_val = MMU.load_uint128(tmp_addr);
		tmp_cap.from128(tmp_val);
		UPDATE_RC_DOWN(STATE.cap_pc.node_id);
		STATE.cap_pc = tmp_cap;
		set_pc(tmp_cap.cursor);
		next_pc_is_cap = true;
	}
	else {
		SET_CAP_ACCESS();
		tmp_data = MMU.load_uint64(tmp_addr);
		UPDATE_RC_DOWN(STATE.cap_pc.node_id);
		STATE.cap_pc.reset();
		set_pc(tmp_data);
	}
	/*ceh*/
	tmp_addr += CLENBYTES;
	SET_CAP_ACCESS();
	tmp_val = MMU.load_uint128(tmp_addr);
	tmp_cap.from128(tmp_val);
	UPDATE_RC_DOWN(STATE.ceh.cap.node_id);
	STATE.ceh.cap = tmp_cap;
	/*csp*/
	tmp_addr += CLENBYTES;
	if (GET_TAG(tmp_addr)) {
		SET_CAP_ACCESS();
		tmp_val = MMU.load_uint128(tmp_addr);
		tmp_cap.from128(tmp_val);
		if (IS_CAP(csp_index)) {
			UPDATE_RC_DOWN(READ_CAP_NODE(csp_index));
		}
		WRITE_CAP_DUMB(csp_index, tmp_cap);
	}
	else {
		SET_CAP_ACCESS();
		tmp_data = MMU.load_uint64(tmp_addr);
		WRITE_DATA(csp_index, tmp_data);
	}
	/*cra*/
	READ_CAP(cra_index).type = CAP_TYPE_EXIT;
	READ_CAP(cra_index).cursor = READ_CAP(cra_index).base;
	/*switch_reg & exit_reg*/
	STATE.switch_reg = insn_rs1;
	STATE.exit_reg = insn_rd;
	/*switch to secure world*/
	TO_SECURE_WORLD();
}
/*asynchronous: exception/interrupt*/
else {
	/*rs1 -> switch_cap*/
	UPDATE_RC_DOWN(STATE.switch_cap.cap.node_id);
	STATE.switch_cap.cap = READ_CAP(insn_rs1);
	RESET_REG(insn_rs1);
	/*normal_pc & normal_sp*/
	STATE.normal_pc = STATE.pc;
	if (IS_CAP(csp_index)) {
		STATE.normal_sp_cap.set_cap(READ_CAP(csp_index));
	}
	else {
		STATE.normal_sp_cap.set_data();
		STATE.normal_sp = READ_REG(csp_index);
	}
	/*pc*/
	uint64_t tmp_addr = STATE.switch_cap.cap.base;
	cap64_t tmp_cap;
	SET_CAP_ACCESS();
	uint128_t tmp_val = MMU.load_uint128(tmp_addr);
	tmp_cap.from128(tmp_val);
	UPDATE_RC_UP(tmp_cap.node_id);
	UPDATE_RC_DOWN(STATE.cap_pc.node_id);
	STATE.cap_pc = tmp_cap;
	set_pc(tmp_cap.cursor);
	/*ceh*/
	tmp_addr += CLENBYTES;
	SET_CAP_ACCESS();
	tmp_val = MMU.load_uint128(tmp_addr);
	tmp_cap.from128(tmp_val);
	UPDATE_RC_UP(tmp_cap.node_id);
	UPDATE_RC_DOWN(STATE.ceh.cap.node_id);
	STATE.ceh.cap = tmp_cap;
	/*31 GPRs*/
	for (uint64_t i = 1; i < 32; i++) {
		tmp_addr += CLENBYTES;
		SET_CAP_ACCESS();
		if (GET_TAG(tmp_addr)) {
			tmp_val = MMU.load_uint128(tmp_addr);
			tmp_cap.from128(tmp_val);
			UPDATE_RC_DOWN(READ_CAP_NODE(i));
			UPDATE_RC_UP(tmp_cap.node_id);
			WRITE_CAP_DUMB(i, tmp_cap);
		}
		else {
			WRITE_DATA(i, MMU.load_uint64(tmp_addr));
		}
	}
	/*switch_cap*/
	STATE.switch_cap.cap.type = CAP_TYPE_UNINITIALIZED;
	STATE.switch_cap.cap.cursor = STATE.switch_cap.cap.base;
	/*switch_reg & exit_reg*/
	STATE.switch_reg = insn_rs1;
	STATE.exit_reg = insn_rd;
	/*switch to secure world*/
	TO_SECURE_WORLD();
}
