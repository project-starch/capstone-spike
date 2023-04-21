require_transcapstone;

if(p->is_cap_debug_enabled() == false) require_privilege(PRV_S);
p->get_secure_mem_init_cap().set_cap(READ_CAP(Rs1));
RESET_REG(Rs1);
