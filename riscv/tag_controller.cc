#include "tag_controller.h"

// TODO: handle the unaligned case more carefully
word_tag_t
TagController::getTag(uint64_t addr) const {
  addr &= ~(WORD_SIZE - 1);
  auto it = taggedAddresses.find(addr);
  return it == taggedAddresses.end() ? WORD_TAG_DATA : WORD_TAG_CAP;
}

void
TagController::setTag(uint64_t addr, word_tag_t tag) {
  addr &= ~(WORD_SIZE - 1);
  if(tag == WORD_TAG_DATA) {
    taggedAddresses.erase(addr);
  } else{
    taggedAddresses.insert(addr);
  }
}
