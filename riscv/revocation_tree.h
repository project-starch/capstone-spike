#ifndef __CAPSTONE_REVOCATION_TREE_H__
#define __CAPSTONE_REVOCATION_TREE_H__

#include <stdlib.h>
#include <string.h>
#include <cstdint>
#include <stack>

typedef uint64_t rev_node_id_t;

const rev_node_id_t REV_NODE_ID_INVALID = (rev_node_id_t)(-1LL);

typedef enum {
  REV_NODE_FREE,
  REV_NODE_INVALID,
  REV_NODE_VALID
} RevNodeState;

struct RevNode {
  RevNodeState state;
  uint64_t ref_count;
  RevNode *next, *children;
};

class RevTree {
private:
  int size, node_brk;
  RevNode* nodes;
  RevNode* free_nodes; // free list
  
  std::stack<RevNode*> traverse_stack;
  
  RevNode* getNewNode();
  void tryFreeing(RevNode* node);

public:
  RevTree(int size) : size(size), node_brk(0) {
    nodes = (RevNode*)malloc(sizeof(RevNode) * size);
    free_nodes = nullptr;
  }

  ~RevTree() {
    free(nodes);
  }
  

  void updateRC(rev_node_id_t node_id, int delta);
  bool allocate(rev_node_id_t parent_id); // allocate a new revocation node and attach to parent
  void revoke(rev_node_id_t node_id); // revoke subtree rooted at node
  RevNode* getNode(rev_node_id_t node_id);
  
  int getSize() const {
    return size;
  }

};

#endif
