if(p->is_cap_debug_enabled() == false) require_secure_world;

// Rs1: target_reg, it holds the target cap_pc

VALID_CAP(Rs1);
cap64_t cap = READ_CAP(Rs1);
assert(cap.accessible() && cap.executable());
set_pc(cap.cursor);
UPDATE_RC_DOWN(p->get_state()->cap_pc.node_id);
p->get_state()->cap_pc = cap;
