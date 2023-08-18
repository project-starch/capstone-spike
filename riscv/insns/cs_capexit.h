// #include "decode.h"
// #include "trap.h"
require_transcapstone;

/*exception*/
if (IS_NORMAL_WORLD())
	throw trap_capstone_illegal_instruction(insn.bits());
if (!IS_CAP(insn_rs1) || !IS_DATA(insn_rs2))
	throw trap_capstone_unexpected_operand_type(insn.bits());
if (!VALID_CAP(insn_rs1))
	throw trap_capstone_invalid_capability(insn.bits());
if (READ_CAP(insn_rs1).type != CAP_TYPE_EXIT)
	throw trap_capstone_unexpected_cap_type(insn.bits());
/*synchronous exit to normal world*/
cap64_t cap = READ_CAP(insn_rs1);
RESET_REG(insn_rs1);
/*pc*/
STATE.cap_pc.cursor = RS2;
uint64_t tmp_addr = cap.base;
SET_CAP_ACCESS();
MMU.store_uint128(tmp_addr, STATE.cap_pc.to128());
/*ceh*/
tmp_addr += CLENBYTES;
SET_CAP_ACCESS();
MMU.store_uint128(tmp_addr, STATE.ceh.cap.to128());
/*csp*/
tmp_addr += CLENBYTES;
SET_CAP_ACCESS();
if (IS_CAP(csp_index)) {
	MMU.store_uint128(tmp_addr, READ_CAP(csp_index).to128());
}
else {
	MMU.store_uint128(tmp_addr, STATE.XPR[csp_index]);
}
/*normal_pc & normal_sp*/
set_pc(STATE.normal_pc + 4);
if (STATE.normal_sp_cap.is_cap()) {
	UPDATE_RC_DOWN(READ_CAP_NODE(csp_index));
	WRITE_CAP_DUMB(csp_index, STATE.normal_sp_cap.cap);
}
else {
	WRITE_DATA(csp_index, STATE.normal_sp);
}
/*x[switch_reg]*/
cap.type = CAP_TYPE_SEALED;
cap.async = CAP_ASYNC_SYNC;
UPDATE_RC_DOWN(READ_CAP_NODE(STATE.switch_reg));
WRITE_CAP_DUMB(STATE.switch_reg, cap);
/*x[exit_reg]*/
WRITE_DATA(STATE.exit_reg, 0);
/*switch to normal world*/
TO_NORMAL_WORLD();
