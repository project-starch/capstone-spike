require_extension(EXT_ZPN);
sreg_t rs1 = static_cast<sreg_t>(RS1);
sreg_t rs2 = static_cast<sreg_t>(RS2);
sreg_t carry = (rs1 & 1) | (rs2 & 1);
WRITE_RD(sext_xlen((rs1 >> 1) + (rs2 >> 1) + carry));
