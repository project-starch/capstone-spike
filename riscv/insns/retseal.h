if(p->is_cap_debug_enabled() == false) require_secure_world;

// Rd: sealret_reg, it is the register that holds the sealret capability
// Rs1: npc_reg, it is the register that holds the cursor for current npc

VALID_CAP(Rd);
cap64_t cap = READ_CAP(Rd);
RESET_REG(Rd);
size_t regfile_size = STATE.XPR.size();
assert(cap.type == CAP_TYPE_SEALEDRET && cap.end - cap.base >= (regfile_size + 1) * 16);
cap.type = CAP_TYPE_SEALED;

cap64_t tmp_cap;
if (p->is_cap_debug_enabled() == false) {
	assert(GET_TAG(cap.base));
	SET_CAP_ACCESS();
	tmp_cap.from128(MMU.load_uint128(cap.base));
	assert(tmp_cap.accessible() && tmp_cap.executable());
	npc = tmp_cap.cursor;
	cap64_t old_pc = p->get_state()->cap_pc;
	assert(IS_DATA(Rs1));
	old_pc.cursor = READ_REG(Rs1);
	RESET_REG(Rs1);
	SET_CAP_ACCESS();
	MMU.store_uint128(cap.base, old_pc.to128());
	p->get_state()->cap_pc = tmp_cap;
}
else{
	SET_CAP_ACCESS();
	npc = MMU.load_uint64(cap.base);
	SET_CAP_ACCESS();
	MMU.store_uint64(cap.base, READ_REG(Rs1));
}

assert(!GET_TAG(cap.base + 16));
uint64_t tmp;
SET_CAP_ACCESS();
tmp = MMU.load_uint64(cap.base + 16);
SET_CAP_ACCESS();
MMU.store_uint64(cap.base + 16, p->get_state()->mtvec->read());
p->set_csr(CSR_MTVEC, tmp);

for (size_t i=1; i < regfile_size; i++) {
	uint64_t cur_addr = cap.base + (i + 1) * 16;
	bool is_cap = IS_CAP(i);
	if (is_cap) tmp_cap = READ_CAP(i);
	else tmp = READ_REG(i);
	if (GET_TAG(cur_addr)) {
		SET_CAP_ACCESS();
		WRITE_CAP_DUMB(i, MMU.load_uint128(cur_addr));
	}
	else {
		SET_CAP_ACCESS();
		WRITE_REG_DUMB(i, MMU.load_uint64(cur_addr));
	}

	if(is_cap) {
		SET_CAP_ACCESS();
		MMU.store_uint128(cur_addr, tmp_cap.to128());
		SET_TAG(cur_addr, true);
	}
	else {
		SET_CAP_ACCESS();
		MMU.store_uint64(cur_addr, tmp);
		SET_TAG(cur_addr, false);
	}
}

WRITE_CAP(Rd, cap);
