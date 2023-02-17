#ifndef __CAPSTONE_TAG_CONTROLLER_H__
#define __CAPSTONE_TAG_CONTROLLER_H__

#include "cap.h"
#include <unordered_set>

const uint64_t WORD_SIZE = 16;

class TagController
{
private:
    std::unordered_set<uint64_t> taggedAddresses;

public:
    void setTag(uint64_t addr, word_tag_t tag);
    word_tag_t getTag(uint64_t addr) const;
};

#endif
