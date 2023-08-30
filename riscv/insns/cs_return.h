// #include "decode.h"
// #include "trap.h"

/*exception*/
if (IS_NORMAL_WORLD())
	throw trap_capstone_illegal_instruction(insn.bits());
if (NOT_ZERO_REG(insn_rs1) && !IS_CAP(insn_rs1))
	throw trap_capstone_unexpected_operand_type(insn.bits());
if (!IS_DATA(insn_rs2))
	throw trap_capstone_unexpected_operand_type(insn.bits());
if (NOT_ZERO_REG(insn_rs1) && !VALID_CAP(insn_rs1))
	throw trap_capstone_invalid_capability(insn.bits());
if (NOT_ZERO_REG(insn_rs1) && READ_CAP(insn_rs1).type != CAP_TYPE_SEALEDRET)
	throw trap_capstone_unexpected_cap_type(insn.bits());
if (NOT_ZERO_REG(insn_rs1) && READ_CAP(insn_rs1).async == CAP_ASYNC_INTERRUPT)
	throw trap_capstone_unexpected_cap_type(insn.bits());
/*rs1 = 0, used for in-domain exception handling return*/
if (insn_rs1 == 0) {
	STATE.cap_pc.cursor = RS2;
	/*pc -> ceh*/
	UPDATE_RC_DOWN(STATE.ceh.cap.node_id);
	STATE.ceh.cap = STATE.cap_pc;
	/*epc -> pc*/
	STATE.cap_pc = STATE.epc.cap;
	set_pc(STATE.cap_pc.cursor);
	/*linearity: epc*/
	if (STATE.epc.cap.is_linear()) {
		STATE.epc.cap.reset();
	}
	else {
		UPDATE_RC_UP(STATE.epc.cap.node_id);
	}
}
else {
	cap_async_t tmp_async = READ_CAP(insn_rs1).async;
	/*synchronous, used in domain switching*/
	if (tmp_async == CAP_ASYNC_SYNC) {
		/*rs1 -> cap*/
		cap64_t cap = READ_CAP(insn_rs1);
		RESET_REG(insn_rs1);
		/*pc*/
		uint64_t tmp_addr = cap.base;
		uint128_t tmp_val;
		cap64_t tmp_cap;
		uint64_t tmp_data;
		STATE.cap_pc.cursor = RS2;
		if (GET_TAG(tmp_addr)) {
			SET_CAP_ACCESS();
			tmp_val = MMU.load_uint128(tmp_addr);
			tmp_cap.from128(tmp_val);
			SET_CAP_ACCESS();
			MMU.store_uint128(tmp_addr, STATE.cap_pc.to128());
			STATE.cap_pc = tmp_cap;
			set_pc(tmp_cap.cursor);
		}
		else {
			SET_CAP_ACCESS();
			tmp_data = MMU.load_uint64(tmp_addr);
			SET_CAP_ACCESS();
			MMU.store_uint128(tmp_addr, STATE.cap_pc.to128());
			STATE.cap_pc.reset();
			set_pc(tmp_data);
			next_pc_is_cap = false;
		}
		/*ceh*/
		tmp_addr += CLENBYTES;
		SET_CAP_ACCESS();
		tmp_val = MMU.load_uint128(tmp_addr);
		tmp_cap.from128(tmp_val);
		SET_CAP_ACCESS();
		MMU.store_uint128(tmp_addr, STATE.ceh.cap.to128());
		STATE.ceh.cap = tmp_cap;
		/*csp*/
		tmp_addr += CLENBYTES;
		if (GET_TAG(tmp_addr)) {
			SET_CAP_ACCESS();
			tmp_val = MMU.load_uint128(tmp_addr);
			tmp_cap.from128(tmp_val);
			SET_CAP_ACCESS();
			if (IS_CAP(csp_index)) {
				MMU.store_uint128(tmp_addr, READ_CAP(csp_index).to128());
			}
			else {
				MMU.store_uint64(tmp_addr, READ_REG(csp_index));
			}
			WRITE_CAP_DUMB(csp_index, tmp_cap);
		}
		else {
			SET_CAP_ACCESS();
			tmp_data = MMU.load_uint64(tmp_addr);
			SET_CAP_ACCESS();
			if (IS_CAP(csp_index)) {
				MMU.store_uint128(tmp_addr, READ_CAP(csp_index).to128());
			}
			else {
				MMU.store_uint64(tmp_addr, READ_REG(csp_index));
			}
			WRITE_DATA_DUMB(csp_index, tmp_data);
		}
		/*write to x[reg]*/
		assert(cap.reg != 0); // dev check
		WRITE_CAP(cap.reg, cap);
		READ_CAP(cap.reg).type = CAP_TYPE_SEALED;
	}
	/*exception, used for exception handling domain return*/
	else if (tmp_async == CAP_ASYNC_EXCEPTION) {
		/*pc*/
		STATE.cap_pc.cursor = RS2;
		uint64_t tmp_addr = READ_CAP(insn_rs1).base;
		uint128_t tmp_val;
		uint64_t tmp_data;
		if (GET_TAG(tmp_addr)) {
			SET_CAP_ACCESS();
			tmp_val = MMU.load_uint128(tmp_addr);
			cap64_t tmp_cap;
			tmp_cap.from128(tmp_val);
			SET_CAP_ACCESS();
			MMU.store_uint128(tmp_addr, STATE.cap_pc.to128());
			STATE.cap_pc = tmp_cap;
			set_pc(tmp_cap.cursor);
		}
		else {
			SET_CAP_ACCESS();
			tmp_data = MMU.load_uint64(tmp_addr);
			SET_CAP_ACCESS();
			MMU.store_uint128(tmp_addr, STATE.cap_pc.to128());
			STATE.cap_pc.reset();
			set_pc(tmp_data);
			next_pc_is_cap = false;
		}
		/*ceh*/
		tmp_addr += CLENBYTES;
		STORE_UPDATE_RC(tmp_addr);
		SET_CAP_ACCESS();
		MMU.store_uint128(tmp_addr, STATE.ceh.cap.to128());
		/*rs1*/
		READ_CAP(insn_rs1).type = CAP_TYPE_SEALED;
		READ_CAP(insn_rs1).async = CAP_ASYNC_SYNC;
		/*rs1 -> ceh*/
		STATE.ceh.cap = READ_CAP(insn_rs1);
		RESET_REG(insn_rs1);
		/*31 GPRs*/
		for (uint64_t i = 1; i < 32; i++) {
			tmp_addr += CLENBYTES;
			// memory
			bool mem_is_cap = GET_TAG(tmp_addr);
			SET_CAP_ACCESS();
			if (mem_is_cap) {
				tmp_val = MMU.load_uint128(tmp_addr);
				tmp_cap.from128(tmp_val);
			}
			else {
				tmp_data = MMU.load_uint64(tmp_addr);
			}
			// register
			bool reg_is_cap = IS_CAP(i);
			SET_CAP_ACCESS();
			if (reg_is_cap) {
				MMU.store_uint128(tmp_addr, READ_CAP(i).to128());
			}
			else {
				MMU.store_uint64(tmp_addr, READ_REG(i));
			}
			// update register
			if (mem_is_cap) {
				WRITE_CAP_DUMB(i, tmp_cap);
			}
			else {
				WRITE_DATA_DUMB(i, tmp_data);
			}
		}
	}
	// /*interrupt, used for interrupt handling domain return*/
	// /*only reachable in pure capstone*/
	// else {
	// 	assert(tmp_async == CAP_ASYNC_INTERRUPT); // dev check
	// 	assert(IS_PURE_CAPSTONE); // dev check
	// 	// TODO
	// }
}