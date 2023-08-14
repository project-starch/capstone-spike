// #include "decode.h"
// #include "trap.h"

bool capability_access = (IS_SECURE_WORLD() || (CSR(CSR_EMODE) == CAP_ENCODING_MODE));
/*capability access*/
if (capability_access) {
	/*exception*/
	if (!IS_CAP(insn_rs1))
		throw trap_capstone_unexpected_operand_type(insn.bits());
	if (!VALID_CAP(insn_rs1))
		throw trap_capstone_invalid_capability(insn.bits());
	cap_type_t tmp_type = READ_CAP(insn_rs1).type;
	if (tmp_type == CAP_TYPE_REVOCATION || tmp_type == CAP_TYPE_UNINITIALIZED || tmp_type == CAP_TYPE_SEALED)
		throw trap_capstone_unexpected_cap_type(insn.bits());
	if (tmp_type == CAP_TYPE_SEALEDRET && READ_CAP(insn_rs1).async != CAP_ASYNC_SYNC)
		throw trap_capstone_unexpected_cap_type(insn.bits());
	if ((tmp_type == CAP_TYPE_LINEAR || tmp_type == CAP_TYPE_NONLINEAR) && !CAP_PERM_GTE(insn_rs1, CAP_PERM_R))
		throw trap_capstone_insufficient_cap_perms(insn.bits());
	uint64_t tmp_addr = READ_CAP(insn_rs1).cursor + insn_i_imm;
	uint64_t tmp_base = READ_CAP(insn_rs1).base;
	uint64_t tmp_end = READ_CAP(insn_rs1).end;
	if ((tmp_type == CAP_TYPE_LINEAR || tmp_type == CAP_TYPE_NONLINEAR) && (tmp_addr < tmp_base || tmp_addr > tmp_end - CLENBYTES))
		throw trap_capstone_cap_out_of_bound(insn.bits());
	if ((tmp_type == CAP_TYPE_SEALEDRET || tmp_type == CAP_TYPE_EXIT) && (tmp_addr < tmp_base + 3 * CLENBYTES || tmp_addr > tmp_base + 32 * CLENBYTES))
		throw trap_capstone_cap_out_of_bound(insn.bits());
	if (tmp_addr % CLENBYTES != 0)
		throw trap_capstone_load_address_misaligned(insn.bits());
	if (GET_TAG(tmp_addr) == false)
		throw trap_capstone_load_access_fault(insn.bits());
	// load the content at the memory location
	cap64_t tmp_cap;
	SET_CAP_ACCESS();
	uint128_t tmp_val = MMU.load_uint128(tmp_addr);
	tmp_cap.from128(tmp_val);
	if ((tmp_type == CAP_TYPE_LINEAR || tmp_type == CAP_TYPE_NONLINEAR) && tmp_cap.is_linear() && !CAP_PERM_GTE(insn_rs1, CAP_PERM_W))
		throw trap_capstone_insufficient_cap_perms(insn.bits());
	/*load a capability*/
	if (WRITE_CAP(insn_rd, tmp_cap)) {
		MMU.store_uint128(tmp_addr, uint128_t(0));
	}
	else {
		UPDATE_RC_UP(READ_CAP_NODE(insn_rd));
	}
}
/*raw address access*/
else {
	/*exception*/
	if (!IS_DATA(insn_rs1))
		throw trap_capstone_unexpected_cap_type(insn.bits());
	uint64_t tmp_addr = RS1 + insn_i_imm;
	if (tmp_addr % CLENBYTES != 0)
		throw trap_capstone_load_address_misaligned(insn.bits());
	// [SBASE, SEND) check is handle in mmu
	if (GET_TAG(tmp_addr) == false)
		throw trap_capstone_load_access_fault(insn.bits());
	/*load a capability*/
	SET_CAP_ACCESS();
	cap64_t tmp_cap;
	uint128_t tmp_val = MMU.load_uint128(tmp_addr);
	tmp_cap.from128(tmp_val);
	if (WRITE_CAP(insn_rd, tmp_cap)) {
		MMU.store_uint128(tmp_addr, uint128_t(0));
	}
	else {
		UPDATE_RC_UP(READ_CAP_NODE(insn_rd));
	}
}
