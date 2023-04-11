require_capstone_debug;
if (STATE.XPR.is_data(Rs1)) {
	printf("(x%u) Data: 0x%lx\n", Rs1, STATE.XPR[Rs1]);
	fflush(stdout);
}
else {
	cap64_t cap = READ_CAP(Rs1);
	printf("(x%u) Capability: (0x%lx, 0x%lx), 0x%lx, perm = %u, type = %u, node = %u\n", Rs1, cap.base, cap.end, cap.cursor, cap.perm, cap.type, cap.node_id);
	fflush(stdout);
}
