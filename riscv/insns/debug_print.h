require_capstone_debug;
if (STATE.XPR.is_data(reg)) {
  printf("Data: %llu\n", STATE.XPR[reg]);
  fflush(stdout);
}
else {
	cap64_t cap = READ_CAP(reg);
	printf("Capability: (%llx, %llx), %llx, perm = %u, type = %u, node = %lu\n", cap.base, cap.end, cap.cursor, cap.perm, cap.type, cap.node_id);
	fflush(stdout);
}