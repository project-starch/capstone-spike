require_capstone_debug;
if (STATE.XPR.is_data(Rs1)) {
	printf("Data: %lu\n", STATE.XPR[Rs1]);
	fflush(stdout);
}
else {
	cap64_t cap = READ_CAP(Rs1);
	printf("Capability: (%lx, %lx), %lx, perm = %u, type = %u, node = %u\n", cap.base, cap.end, cap.cursor, cap.perm, cap.type, cap.node_id);
	fflush(stdout);
}
