require_privilege(PRV_S);
if (p->get_secure_mem_init_cap().is_cap()) {
    WRITE_CAP(Rd, p->get_secure_mem_init_cap().cap);
    p->get_secure_mem_init_cap().reset();
}
