#include <cassert>
#include "revocation_tree.h"

rev_node_id_t
RevTree::allocate(rev_node_id_t parent_id) {
  RevNode* parent_node = getNode(parent_id);
  RevNode* new_node = getNewNode();
  if(!new_node) {
    return REV_NODE_ID_INVALID; // unable to allocate new node
  }

  new_node->state = REV_NODE_VALID;
  new_node->type = REV_NODE_LINEAR;
  new_node->children = nullptr;
  new_node->ref_count = 1;
  new_node->prev = nullptr;
  new_node->parent = parent_node;

  if(parent_node) {
    assert(parent_node->state == REV_NODE_VALID); // must be in a valid tree
    new_node->next = parent_node->children;
    new_node->next->prev = new_node;
    parent_node->children = new_node;
  } else{
    // if the parent is null, the new node becomes a root node
    new_node->next = nullptr;
  }
  
  rev_node_id_t new_node_id = new_node - nodes;
  return new_node_id;
}

rev_node_id_t
RevTree::split(rev_node_id_t node_id) {
  // This function assumes that the node is a linear cap
  RevNode* node = getNode(node_id);
  if(!node || node->state != REV_NODE_VALID) {
    return REV_NODE_ID_INVALID;
  }
  RevNode* new_node = getNewNode();
  if(!new_node) {
    return REV_NODE_ID_INVALID; // unable to allocate new node
  }
  new_node->state = REV_NODE_VALID;
  new_node->type = REV_NODE_LINEAR;
  new_node->children = nullptr;
  new_node->ref_count = 1;
  new_node->prev = node;
  new_node->parent = node->parent;
  new_node->next = node->next;
  node->next = new_node;

  rev_node_id_t new_node_id = new_node - nodes;
  return new_node_id;
}

void
RevTree::updateRC(rev_node_id_t node_id, int delta){
  RevNode* node = getNode(node_id);
  node->ref_count += delta;
  tryFreeing(node);
}

void
RevTree::set_nonlinear(rev_node_id_t node_id) {
  RevNode* node = getNode(node_id);
  node->type = REV_NODE_NONLINEAR;
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

bool
RevTree::revoke(rev_node_id_t node_id) {
  bool all_nonlinear = true;

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
    if(all_nonlinear && node->type == REV_NODE_LINEAR) all_nonlinear = false;

    for(RevNode* child = node->children; child; child = child->next) {
      traverse_stack.push(child);
    }
    
    tryFreeing(node);
  }
  
  // remove the children
  root_node->children = nullptr;

  return all_nonlinear;
}

void
RevTree::drop(rev_node_id_t node_id) {
  RevNode* node = getNode(node_id);
  if(!node) return;
  RevNode* parent = node->parent;
  RevNode* prev = node->prev;
  RevNode* next = node->next;
  RevNode* child = node->children;

  if (child) {
    if (prev) {
      prev->next = child;
    }
    else {
      if (parent) parent->children = child;
    }

    RevNode* c = child;
    while (c->next != nullptr) c = c->next;
    c->next = next;
    node->state = REV_NODE_INVALID;
    tryFreeing(node);
  }
  else {
    if (prev) {
      prev->next = next;
    }
    else {
      if (parent) parent->children = next;
    }
    node->state = REV_NODE_INVALID;
    tryFreeing(node);
  }
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
    node_id >= static_cast<uint64_t>(size)) {
    return nullptr;
  }
  return nodes + node_id;
}
