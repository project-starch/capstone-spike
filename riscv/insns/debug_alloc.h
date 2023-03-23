require_capstone_debug;
rev_node_id_t node_id = p->allocate(READ_CAP_NODE(Rs1));
WRITE_REG(Rd, node_id);