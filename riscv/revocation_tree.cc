#include <cassert>
#include "revocation_tree.h"

bool
RevTree::allocate(rev_node_id_t parent_id) {
  RevNode* parent_node = getNode(parent_id);
  RevNode* new_node = getNewNode();
  if(!new_node) {
    return false; // unable to allocate new node
  }

  new_node->state = REV_NODE_VALID;
  new_node->children = nullptr;
  new_node->ref_count = 1;

  if(parent_node) {
    assert(parent_node->state == REV_NODE_VALID); // must be in a valid tree
    new_node->next = parent_node->children;
    parent_node->children = new_node;
  } else{
    // if the parent is null, the new node becomes a root node
    new_node->next = nullptr;
  }
  
  return true;
}

void
RevTree::updateRC(rev_node_id_t node_id, int delta){
  RevNode* node = getNode(node_id);
  node->ref_count += delta;
  tryFreeing(node);
}

void
RevTree::tryFreeing(RevNode* node) {
  if(node->state == REV_NODE_INVALID && node->ref_count == 0) {
    // add to free list
    node->state = REV_NODE_FREE;
    node->next = free_nodes;
    free_nodes = node;
  }
}

void
RevTree::revoke(rev_node_id_t node_id) {
  RevNode* root_node = getNode(node_id);
  if(!root_node)
    return;
  for(RevNode* node = root_node->children; node; node = node->next) {
    traverse_stack.push(node);
  }
  while(!traverse_stack.empty()) {
    RevNode* node = traverse_stack.top();
    traverse_stack.pop();
    assert(node->state == REV_NODE_VALID);
    node->state = REV_NODE_INVALID;

    for(RevNode* child = node->children; child; child = child->next) {
      traverse_stack.push(child);
    }
    
    tryFreeing(node);
  }
  
  // remove the children
  root_node->children = nullptr;
}


RevNode*
RevTree::getNewNode() {
  if(free_nodes) {
    RevNode* res = free_nodes;
    free_nodes = res->next;
    return res;
  }
  if(node_brk < size) {
    RevNode* res = nodes + node_brk;
    ++ node_brk;
    return res;
  }
  return nullptr;
}


RevNode*
RevTree::getNode(rev_node_id_t node_id) {
  if(node_id == REV_NODE_ID_INVALID ||
    node_id >= size) {
    return nullptr;
  }
  return nodes + node_id;
}