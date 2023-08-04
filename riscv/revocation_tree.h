#ifndef __CAPSTONE_REVOCATION_TREE_H__
#define __CAPSTONE_REVOCATION_TREE_H__

#include <stdlib.h>
#include <string.h>
#include <cstdint>
#include <stack>

typedef uint32_t rev_node_id_t;

const rev_node_id_t REV_NODE_ID_INVALID = uint32_t((-1) & (((uint32_t)1 << 31) - 1));

typedef enum {
  REV_NODE_FREE, // revoked and rc is 0 (i.e. ready to be reused)
  REV_NODE_INVALID, // revoked
  REV_NODE_VALID // corresponds to the valid field of a capability
} RevNodeState;

// RevNodeType is maintained for the use in REVOKE
typedef enum {
  REV_NODE_LINEAR,
  REV_NODE_NONLINEAR
} RevNodeType;

struct RevNode {
  RevNodeState state;
  RevNodeType type;
  uint64_t ref_count;
  RevNode *prev, *next, *children, *parent;
};

class RevTree {
private:
  int size, node_brk;
  RevNode* nodes; // all nodes available in the system
  RevNode* free_nodes; // free list
  
  std::stack<RevNode*> traverse_stack;
  
  /*internal interfaces*/
  RevNode* getNewNode();
  RevNode* getNode(rev_node_id_t node_id);
  void tryFreeing(RevNode* node);

public:
  RevTree(int size) : size(size), node_brk(0) {
    nodes = (RevNode*)malloc(sizeof(RevNode) * size);
    free_nodes = nullptr;
  }

  ~RevTree() {
    free(nodes);
  }
  
  /*rev_tree update interface*/
  // update the ref_count of a node
  void updateRC(rev_node_id_t node_id, int delta);
  // allocate a new revocation node and attach to the parent node
  rev_node_id_t allocate(rev_node_id_t parent_id);
  // split the node of a linear capability into two sibling nodes
  rev_node_id_t split(rev_node_id_t node_id);
  // revoke a node and its subtree
  bool revoke(rev_node_id_t node_id);
  // drop the node of a linear capability
  void drop(rev_node_id_t node_id);
  // set a node's type to nonlinear
  void set_nonlinear(rev_node_id_t node_id);
  
  int getSize() const {
    return size;
  }

  bool is_valid(rev_node_id_t node_id) {
    RevNode* node = getNode(node_id);
    return node && node->state == REV_NODE_VALID;
  }
};

#endif
