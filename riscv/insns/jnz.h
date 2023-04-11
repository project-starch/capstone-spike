if(p->is_cap_debug_enabled() == false) require_secure_world;

// Rd: target_reg, it holds the target cap_pc
// Rs1: check_reg

if (RS1 != 0) {
    VALID_CAP(Rd);
    cap64_t cap = READ_CAP(Rd);
    assert(cap.accessible() && cap.executable());
    set_pc(cap.cursor);
    UPDATE_RC_DOWN(p->get_state()->cap_pc.node_id);
    p->get_state()->cap_pc = cap;
}
