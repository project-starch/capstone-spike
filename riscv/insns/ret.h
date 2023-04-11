if(p->is_cap_debug_enabled() == false) require_secure_world;

// Rd: sealret_reg, it is the register that holds the sealret capability
// Rs1: retval_reg, it is the register that holds the return value

VALID_CAP(Rd);
cap64_t cap = READ_CAP(Rd);
MOVE(Rd, Rs1);
size_t regfile_size = STATE.XPR.size();
assert(cap.type == CAP_TYPE_SEALEDRET && cap.end - cap.base >= (regfile_size + 1) * 16);

cap64_t tmp_cap;
uint64_t tmp;
if (p->is_cap_debug_enabled() == false) {
	assert(GET_TAG(cap.base));
	SET_CAP_ACCESS();
	tmp_cap.from128(MMU.load_uint128(cap.base));
	assert(tmp_cap.accessible() && tmp_cap.executable());
	set_pc(tmp_cap.cursor);
	UPDATE_RC_DOWN(p->get_state()->cap_pc.node_id);
	p->get_state()->cap_pc = tmp_cap;
	SET_TAG(cap.base, false);
	SET_CAP_ACCESS();
	MMU.store_uint128(cap.base, uint128_t(0));
}
else {
	SET_CAP_ACCESS();
	tmp = MMU.load_uint64(cap.base);
	set_pc(tmp);
	SET_CAP_ACCESS();
	MMU.store_uint128(cap.base, uint128_t(0));
}

assert(!GET_TAG(cap.base + 16));
SET_CAP_ACCESS();
tmp = MMU.load_uint64(cap.base + 16);
p->set_csr(CSR_MTVEC, tmp);
SET_CAP_ACCESS();
MMU.store_uint128(cap.base + 16, uint128_t(0));

for (size_t i=1; i < regfile_size; i++) {
	uint64_t cur_addr = cap.base + (i + 1) * 16;
	if (GET_TAG(cur_addr)) {
		SET_CAP_ACCESS();
		tmp_cap.from128(MMU.load_uint128(cur_addr));
		if (i != Rd) {
			WRITE_CAP(i, tmp_cap);
			if (!(tmp_cap.is_linear())) UPDATE_RC_DOWN(tmp_cap.node_id);
		}
		else {
			UPDATE_RC_DOWN(tmp_cap.node_id);
		}
		SET_TAG(cur_addr, false);
	}
	else {
		SET_CAP_ACCESS();
		WRITE_REG(i, MMU.load_uint64(cur_addr));
	}
	SET_CAP_ACCESS();
	MMU.store_uint128(cur_addr, uint128_t(0));
}
