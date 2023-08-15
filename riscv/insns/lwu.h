// #include "decode.h"
// #include "trap.h"
require_rv64;

bool capability_access = (IS_SECURE_WORLD() || (CSR(CSR_EMODE) == CAP_ENCODING_MODE));
const uint64_t size = 4;
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
	if ((tmp_type == CAP_TYPE_LINEAR || tmp_type == CAP_TYPE_NONLINEAR) && (tmp_addr < tmp_base || tmp_addr > tmp_end - size))
		throw trap_capstone_cap_out_of_bound(insn.bits());
	if ((tmp_type == CAP_TYPE_SEALEDRET || tmp_type == CAP_TYPE_EXIT) && (tmp_addr < tmp_base + 3 * CLENBYTES || tmp_addr > tmp_base + 33 * CLENBYTES - size))
		throw trap_capstone_cap_out_of_bound(insn.bits());
	if (tmp_addr % size != 0)
		throw trap_capstone_load_address_misaligned(insn.bits());
	/*load a size-byte integer with a capability*/
	SET_CAP_ACCESS();
	WRITE_DATA(insn_rd, MMU.load_uint32(tmp_addr));
}
else {
	WRITE_RD(MMU.load_uint32(RS1 + insn.i_imm()));
}
