// #include "decode.h"
require_capstone_debug;

if (IS_DATA(insn_rd)) {
	printf("(x%u) Data: 0x%lx\n", insn_rd, READ_REG(insn_rd));
	fflush(stdout);
}
else {
	cap64_t tmp_cap = READ_CAP(insn_rd);
	printf("(x%u) Capability: (0x%lx, 0x%lx), 0x%lx, perm = %u, type = %u, node = %u, async = %u, reg = %u\n",
			insn_rd, tmp_cap.base, tmp_cap.end, tmp_cap.cursor, tmp_cap.perm, tmp_cap.type, tmp_cap.node_id, tmp_cap.async, tmp_cap.reg);
	fflush(stdout);
}
