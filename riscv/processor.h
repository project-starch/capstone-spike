// See LICENSE for license details.
#ifndef _RISCV_PROCESSOR_H
#define _RISCV_PROCESSOR_H

#include "decode.h"
#include "config.h"
#include "trap.h"
#include "abstract_device.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <cassert>
#include "debug_rom_defines.h"
#include "entropy_source.h"
#include "csrs.h"
#include "simif.h"

typedef enum
{
  WORLD_NORMAL,
  WORLD_SECURE
} world_type_t;

class processor_t;
class mmu_t;
typedef reg_t (*insn_func_t)(processor_t*, insn_t, reg_t);
class trap_t;
class extension_t;
class disassembler_t;

reg_t illegal_instruction(processor_t* p, insn_t insn, reg_t pc);

struct insn_desc_t
{
  insn_bits_t match;
  insn_bits_t mask;
  insn_func_t rv32i;
  insn_func_t rv64i;
  insn_func_t rv32e;
  insn_func_t rv64e;

  insn_func_t func(int xlen, bool rve)
  {
    if (rve)
      return xlen == 64 ? rv64e : rv32e;
    else
      return xlen == 64 ? rv64i : rv32i;
  }

  static insn_desc_t illegal()
  {
    return {0, 0, &illegal_instruction, &illegal_instruction, &illegal_instruction, &illegal_instruction};
  }
};

// regnum, data
typedef std::unordered_map<uint64_t, freg_t> commit_log_reg_t;

// addr, value, size
typedef std::vector<std::tuple<reg_t, uint64_t, uint8_t>> commit_log_mem_t;

typedef enum
{
  ACTION_DEBUG_EXCEPTION = MCONTROL_ACTION_DEBUG_EXCEPTION,
  ACTION_DEBUG_MODE = MCONTROL_ACTION_DEBUG_MODE,
  ACTION_TRACE_START = MCONTROL_ACTION_TRACE_START,
  ACTION_TRACE_STOP = MCONTROL_ACTION_TRACE_STOP,
  ACTION_TRACE_EMIT = MCONTROL_ACTION_TRACE_EMIT
} mcontrol_action_t;

typedef enum
{
  MATCH_EQUAL = MCONTROL_MATCH_EQUAL,
  MATCH_NAPOT = MCONTROL_MATCH_NAPOT,
  MATCH_GE = MCONTROL_MATCH_GE,
  MATCH_LT = MCONTROL_MATCH_LT,
  MATCH_MASK_LOW = MCONTROL_MATCH_MASK_LOW,
  MATCH_MASK_HIGH = MCONTROL_MATCH_MASK_HIGH
} mcontrol_match_t;

typedef struct
{
  uint8_t type;
  bool dmode;
  uint8_t maskmax;
  bool select;
  bool timing;
  mcontrol_action_t action;
  bool chain;
  mcontrol_match_t match;
  bool m;
  bool h;
  bool s;
  bool u;
  bool execute;
  bool store;
  bool load;
} mcontrol_t;

enum VRM{
  RNU = 0,
  RNE,
  RDN,
  ROD,
  INVALID_RM
};

template<uint64_t N>
struct type_usew_t;

template<>
struct type_usew_t<8>
{
  using type=uint8_t;
};

template<>
struct type_usew_t<16>
{
  using type=uint16_t;
};

template<>
struct type_usew_t<32>
{
  using type=uint32_t;
};

template<>
struct type_usew_t<64>
{
  using type=uint64_t;
};

template<uint64_t N>
struct type_sew_t;

template<>
struct type_sew_t<8>
{
  using type=int8_t;
};

template<>
struct type_sew_t<16>
{
  using type=int16_t;
};

template<>
struct type_sew_t<32>
{
  using type=int32_t;
};

template<>
struct type_sew_t<64>
{
  using type=int64_t;
};

// capstone capability-extended register file
template <class T, size_t N>
class regfile_cap_t
{
public:
  regfile_cap_t () {
    zero_reg = true;
  }
  /*init & reset*/
  // reset_i is used to clear a linear capability (set to cnull)
  void reset_i(size_t i) {
    if (i != 0 || !zero_reg) {
      memset(data + i, 0, sizeof(data[i]));
      cap_data[i].reset_i();
    }
  }
  // reset is used in system reset
  void reset(processor_t *proc)
  {
    p = proc;
    memset(data, 0, sizeof(data));
    for (size_t i = 0; i < N; i++) {
      cap_data[i].reset();
    }
  }

  /*reg file interfaces*/
  // checks
  bool is_data(size_t i) const {
    if (i == 0 && zero_reg) return true;
    return cap_data[i].is_data();
  }
  bool is_cap(size_t i) const {
    if (i == 0 && zero_reg) return true;
    return cap_data[i].is_cap();
  }
  // basic operations
  inline size_t size() const { return N; }
  const T& operator [] (size_t i);
  cap64_t& read_cap(size_t i);
  void write(size_t i, T value, bool rc_update=true);
  bool write_cap(size_t i, const cap64_t &cap, bool rc_update=true);
  
  // capability manipulation operations
  void move(size_t to, size_t from);
  void split_cap(size_t reg, size_t split_reg, reg_t pv, rev_node_id_t split_node_id);
  void delin(size_t reg);
  void mrev(size_t reg, size_t cap_reg, rev_node_id_t new_node_id);
  // debugging
  inline void debug_set_cap(size_t i) { cap_data[i].tag = WORD_TAG_CAP; }

private:
  processor_t *p;
  T data[N];
  cap_reg_t cap_data[N];
  bool zero_reg;
};

// architectural state of a RISC-V hart
struct state_t
{
  void reset(processor_t* proc, reg_t max_isa);

  static const int num_triggers = 4;

  reg_t pc;
  /*capstone defined processor states*/
  cap64_t cap_pc;
  bool cap_access; // set to true if the memory access is 
  world_type_t world;
  /*end of capstone defined processor states*/
  regfile_cap_t<reg_t, NXPR> XPR;
  regfile_t<freg_t, NFPR, false> FPR;

  // capability control and status registers (CCSRs)
  ccsr_t ceh;
  ccsr_t epc;
  ccsr_t switch_cap;
  // other shadow registers added in capstone
  uint64_t normal_pc;
  uint64_t normal_sp;
  uint64_t switch_reg;
  uint64_t exit_reg;

  // control and status registers
  std::unordered_map<uint64_t, csr_t_p> csrmap;
  reg_t prv;    // TODO: Can this be an enum instead?
  bool v;
  /*capstone CSRs*/
  csr_t_p tval;
  csr_t_p cause;
  csr_t_p emode;
  /*end of capstone CSRs*/
  misa_csr_t_p misa;
  mstatus_csr_t_p mstatus;
  csr_t_p mepc;
  csr_t_p mtval;
  csr_t_p mtvec;
  csr_t_p mcause;
  minstret_csr_t_p minstret;
  mie_csr_t_p mie;
  mip_csr_t_p mip;
  csr_t_p medeleg;
  csr_t_p mideleg;
  csr_t_p mcounteren;
  csr_t_p scounteren;
  csr_t_p sepc;
  csr_t_p stval;
  csr_t_p stvec;
  virtualized_csr_t_p satp;
  csr_t_p scause;

  csr_t_p mtval2;
  csr_t_p mtinst;
  csr_t_p hstatus;
  csr_t_p hideleg;
  csr_t_p hedeleg;
  csr_t_p hcounteren;
  csr_t_p htval;
  csr_t_p htinst;
  csr_t_p hgatp;
  sstatus_csr_t_p sstatus;
  vsstatus_csr_t_p vsstatus;
  csr_t_p vstvec;
  csr_t_p vsepc;
  csr_t_p vscause;
  csr_t_p vstval;
  csr_t_p vsatp;

  csr_t_p dpc;
  dcsr_csr_t_p dcsr;
  csr_t_p tselect;
  mcontrol_t mcontrol[num_triggers];
  tdata2_csr_t_p tdata2;
  bool debug_mode;

  static const int max_pmp = 16;
  pmpaddr_csr_t_p pmpaddr[max_pmp];

  csr_t_p fflags;
  csr_t_p frm;
  bool serialized; // whether timer CSRs are in a well-defined state

  // When true, execute a single instruction and then enter debug mode.  This
  // can only be set by executing dret.
  enum {
      STEP_NONE,
      STEP_STEPPING,
      STEP_STEPPED
  } single_step;

#ifdef RISCV_ENABLE_COMMITLOG
  commit_log_reg_t log_reg_write;
  commit_log_mem_t log_mem_read;
  commit_log_mem_t log_mem_write;
  reg_t last_inst_priv;
  int last_inst_xlen;
  int last_inst_flen;
#endif
};

typedef enum {
  OPERATION_EXECUTE,
  OPERATION_STORE,
  OPERATION_LOAD,
} trigger_operation_t;

typedef enum {
  // 65('A') ~ 90('Z') is reserved for standard isa in misa
  EXT_ZFH,
  EXT_ZFHMIN,
  EXT_ZBA,
  EXT_ZBB,
  EXT_ZBC,
  EXT_ZBS,
  EXT_ZBKB,
  EXT_ZBKC,
  EXT_ZBKX,
  EXT_ZKND,
  EXT_ZKNE,
  EXT_ZKNH,
  EXT_ZKSED,
  EXT_ZKSH,
  EXT_ZKR,
  EXT_ZMMUL,
  EXT_ZBPBO,
  EXT_ZPN,
  EXT_ZPSFOPERAND,
  EXT_SVNAPOT,
  EXT_SVPBMT,
  EXT_SVINVAL,
  EXT_ZDINX,
  EXT_ZFINX,
  EXT_ZHINX,
  EXT_ZHINXMIN,
  EXT_XBITMANIP,
} isa_extension_t;

typedef enum {
  IMPL_MMU_SV32,
  IMPL_MMU_SV39,
  IMPL_MMU_SV48,
  IMPL_MMU_SBARE,
  IMPL_MMU,
} impl_extension_t;

// Count number of contiguous 1 bits starting from the LSB.
static int cto(reg_t val)
{
  int res = 0;
  while ((val & 1) == 1)
    val >>= 1, res++;
  return res;
}

class isa_parser_t {
public:
  isa_parser_t(const char* str);
  ~isa_parser_t(){};
  unsigned get_max_xlen() { return max_xlen; }
  std::string get_isa_string() { return isa_string; }
  bool extension_enabled(unsigned char ext) const {
    if (ext >= 'A' && ext <= 'Z')
      return (max_isa >> (ext - 'A')) & 1;
    else
      return extension_table[ext];
  }
protected:
  unsigned max_xlen;
  reg_t max_isa;
  std::vector<bool> extension_table;
  std::string isa_string;
  std::unordered_map<std::string, extension_t*> custom_extensions;
};

// this class represents one processor in a RISC-V machine.
class processor_t : public abstract_device_t, public isa_parser_t
{
public:
  processor_t(const char* isa, const char* priv, const char* varch,
              simif_t* sim, uint32_t id, bool halt_on_reset,
              FILE *log_file, std::ostream& sout_); // because of command line option --log and -s we need both
  ~processor_t();

  void set_debug(bool value);
  void set_histogram(bool value);
#ifdef RISCV_ENABLE_COMMITLOG
  void enable_log_commits();
  bool get_log_commits_enabled() const { return log_commits_enabled; }
#endif
  void reset();
  void step(size_t n); // run for n cycles
  void set_csr(int which, reg_t val);
  uint32_t get_id() const { return id; }
  reg_t get_csr(int which, insn_t insn, bool write, bool peek = 0);
  reg_t get_csr(int which) { return get_csr(which, insn_t(0), false, true); }
  mmu_t* get_mmu() { return mmu; }
  state_t* get_state() { return &state; }
  unsigned get_xlen() { return xlen; }
  unsigned get_const_xlen() {
    // Any code that assumes a const xlen should use this method to
    // document that assumption. If Spike ever changes to allow
    // variable xlen, this method should be removed.
    return xlen;
  }
  unsigned get_flen() {
    return extension_enabled('Q') ? 128 :
           extension_enabled('D') ? 64 :
           extension_enabled('F') ? 32 : 0;
  }
  extension_t* get_extension();
  extension_t* get_extension(const char* name);
  bool any_custom_extensions() const {
    return !custom_extensions.empty();
  }
  bool extension_enabled(unsigned char ext) const {
    if (ext >= 'A' && ext <= 'Z')
      return state.misa->extension_enabled(ext);
    else
      return extension_table[ext];
  }
  // Is this extension enabled? and abort if this extension can
  // possibly be disabled dynamically. Useful for documenting
  // assumptions about writable misa bits.
  bool extension_enabled_const(unsigned char ext) const {
    if (ext >= 'A' && ext <= 'Z')
      return state.misa->extension_enabled_const(ext);
    else
      return extension_table[ext];  // assume this can't change
  }
  void set_impl(uint8_t impl, bool val) { impl_table[impl] = val; }
  bool supports_impl(uint8_t impl) const {
    return impl_table[impl];
  }
  reg_t pc_alignment_mask() {
    return ~(reg_t)(extension_enabled('C') ? 0 : 2);
  }
  void check_pc_alignment(reg_t pc) {
    if (unlikely(pc & ~pc_alignment_mask()))
      throw trap_instruction_address_misaligned(state.v, pc, 0, 0);
  }
  reg_t legalize_privilege(reg_t);
  void set_privilege(reg_t);
  void set_virt(bool);
  void update_histogram(reg_t pc);
  const disassembler_t* get_disassembler() { return disassembler; }

  FILE *get_log_file() { return log_file; }

  void register_insn(insn_desc_t);
  void register_extension(extension_t*);

  // MMIO slave interface
  bool load(reg_t addr, size_t len, uint8_t* bytes);
  bool store(reg_t addr, size_t len, const uint8_t* bytes);

  // When true, display disassembly of each instruction that's executed.
  bool debug;
  // When true, take the slow simulation path.
  bool slow_path();
  bool halted() { return state.debug_mode; }
  enum {
    HR_NONE,    /* Halt request is inactive. */
    HR_REGULAR, /* Regular halt request/debug interrupt. */
    HR_GROUP    /* Halt requested due to halt group. */
  } halt_request;

  // Return the index of a trigger that matched, or -1.
  inline int trigger_match(trigger_operation_t operation, reg_t address, reg_t data)
  {
    if (state.debug_mode)
      return -1;

    bool chain_ok = true;

    for (unsigned int i = 0; i < state.num_triggers; i++) {
      if (!chain_ok) {
        chain_ok |= !state.mcontrol[i].chain;
        continue;
      }

      if ((operation == OPERATION_EXECUTE && !state.mcontrol[i].execute) ||
          (operation == OPERATION_STORE && !state.mcontrol[i].store) ||
          (operation == OPERATION_LOAD && !state.mcontrol[i].load) ||
          (state.prv == PRV_M && !state.mcontrol[i].m) ||
          (state.prv == PRV_S && !state.mcontrol[i].s) ||
          (state.prv == PRV_U && !state.mcontrol[i].u)) {
        continue;
      }

      reg_t value;
      if (state.mcontrol[i].select) {
        value = data;
      } else {
        value = address;
      }

      // We need this because in 32-bit mode sometimes the PC bits get sign
      // extended.
      if (xlen == 32) {
        value &= 0xffffffff;
      }

      auto tdata2 = state.tdata2->read(i);
      switch (state.mcontrol[i].match) {
        case MATCH_EQUAL:
          if (value != tdata2)
            continue;
          break;
        case MATCH_NAPOT:
          {
            reg_t mask = ~((1 << (cto(tdata2)+1)) - 1);
            if ((value & mask) != (tdata2 & mask))
              continue;
          }
          break;
        case MATCH_GE:
          if (value < tdata2)
            continue;
          break;
        case MATCH_LT:
          if (value >= tdata2)
            continue;
          break;
        case MATCH_MASK_LOW:
          {
            reg_t mask = tdata2 >> (xlen/2);
            if ((value & mask) != (tdata2 & mask))
              continue;
          }
          break;
        case MATCH_MASK_HIGH:
          {
            reg_t mask = tdata2 >> (xlen/2);
            if (((value >> (xlen/2)) & mask) != (tdata2 & mask))
              continue;
          }
          break;
      }

      if (!state.mcontrol[i].chain) {
        return i;
      }
      chain_ok = true;
    }
    return -1;
  }

  void trigger_updated();

  void set_pmp_num(reg_t pmp_num);
  void set_pmp_granularity(reg_t pmp_granularity);
  void set_mmu_capability(int cap);

  const char* get_symbol(uint64_t addr);

  /*interface defined for capstone*/
  /*ccsr*/
  ccsr_t& get_ccsr(uint64_t ccsr_num) {
    switch (ccsr_num) {
      case CCSR_CEH:
        return state.ceh;
      case CCSR_CINIT:
        return sim->get_cinit();
      case CCSR_EPC:
        return state.epc;
      case CCSR_SWITCH_CAP:
        return state.switch_cap;
      default:
        abort();
    }
  }
  /*revocation tree interface*/
  inline bool valid_cap(rev_node_id_t node_id) const {
    return sim->get_rev_tree().is_valid(node_id);
  }
  inline void updateRC(rev_node_id_t node_id, int delta) const {
    sim->get_rev_tree().updateRC(node_id, delta);
  }
  inline rev_node_id_t split_rt(rev_node_id_t node_id) const {
    return sim->get_rev_tree().split(node_id);
  }
  inline bool revoke(rev_node_id_t node_id) const {
    return sim->get_rev_tree().revoke(node_id);
  }
  inline rev_node_id_t allocate(rev_node_id_t parent_id) const {
    return sim->get_rev_tree().allocate(parent_id);
  }
  inline void set_nonlinear(rev_node_id_t node_id) const {
    sim->get_rev_tree().set_nonlinear(node_id);
  }
  inline void drop(rev_node_id_t node_id) const {
    sim->get_rev_tree().drop(node_id);
  }
  /*tag controller*/
  inline void setTag(uint64_t addr, bool as_cap) {
    sim->get_tag_controller().setTag(addr, as_cap);
  }
  virtual bool getTag(uint64_t addr) {
    return sim->get_tag_controller().getTag(addr);
  }
  /*world related information & operation*/
  inline bool is_normal_access() const {
    return state.world == WORLD_NORMAL && state.cap_access == false;
  }
  inline bool is_secure_world() const {
    return state.world == WORLD_SECURE;
  }
  inline void set_cap_access() {
    state.cap_access = true;
  }
  inline void switch_world(bool to_secure_world) {
    state.world = to_secure_world ? WORLD_SECURE : WORLD_NORMAL;
  }
  /*spike parameters*/
  inline bool is_cap_debug_enabled() const {
    return sim->is_cap_debug_enabled();
  }
  inline bool is_pure_capstone() const {
    return sim->is_pure_capstone();
  }

private:
  simif_t* sim;
  mmu_t* mmu; // main memory is always accessed via the mmu
  std::unordered_map<std::string, extension_t*> custom_extensions;
  disassembler_t* disassembler;
  state_t state;
  uint32_t id;
  unsigned xlen;
  bool histogram_enabled;
  bool log_commits_enabled;
  FILE *log_file;
  std::ostream sout_; // needed for socket command interface -s, also used for -d and -l, but not for --log
  bool halt_on_reset;
  std::vector<bool> impl_table;

  std::vector<insn_desc_t> instructions;
  std::map<reg_t,uint64_t> pc_histogram;

  static const size_t OPCODE_CACHE_SIZE = 8191;
  insn_desc_t opcode_cache[OPCODE_CACHE_SIZE];

  void take_pending_interrupt() { take_interrupt(state.mip->read() & state.mie->read()); }
  void take_interrupt(reg_t mask); // take first enabled interrupt in mask
  void take_trap(trap_t& t, reg_t epc); // take an exception
  void disasm(insn_t insn); // disassemble and print an instruction
  int paddr_bits();

  void enter_debug_mode(uint8_t cause);

  void debug_output_log(std::stringstream *s); // either output to interactive user or write to log file

  friend class mmu_t;
  friend class clint_t;
  friend class extension_t;

  void parse_varch_string(const char*);
  void parse_priv_string(const char*);
  void build_opcode_map();
  void register_base_instructions();
  insn_func_t decode_insn(insn_t insn);

  // Track repeated executions for processor_t::disasm()
  uint64_t last_pc, last_bits, executions;
public:
  entropy_source es; // Crypto ISE Entropy source.

  reg_t n_pmp;
  reg_t lg_pmp_granularity;
  reg_t pmp_tor_mask() { return -(reg_t(1) << (lg_pmp_granularity - PMP_SHIFT)); }

  class vectorUnit_t {
    public:
      processor_t* p;
      void *reg_file;
      char reg_referenced[NVPR];
      int setvl_count;
      reg_t vlmax;
      reg_t vlenb;
      csr_t_p vxsat;
      vector_csr_t_p vxrm, vstart, vl, vtype;
      reg_t vma, vta;
      reg_t vsew;
      float vflmul;
      reg_t ELEN, VLEN;
      bool vill;
      bool vstart_alu;

      // vector element for varies SEW
      template<class T>
        T& elt(reg_t vReg, reg_t n, bool is_write = false){
          assert(vsew != 0);
          assert((VLEN >> 3)/sizeof(T) > 0);
          reg_t elts_per_reg = (VLEN >> 3) / (sizeof(T));
          vReg += n / elts_per_reg;
          n = n % elts_per_reg;
#ifdef WORDS_BIGENDIAN
          // "V" spec 0.7.1 requires lower indices to map to lower significant
          // bits when changing SEW, thus we need to index from the end on BE.
          n ^= elts_per_reg - 1;
#endif
          reg_referenced[vReg] = 1;

#ifdef RISCV_ENABLE_COMMITLOG
          if (is_write)
            p->get_state()->log_reg_write[((vReg) << 4) | 2] = {0, 0};
#endif

          T *regStart = (T*)((char*)reg_file + vReg * (VLEN >> 3));
          return regStart[n];
        }
    public:

      void reset();

      vectorUnit_t():
        p(0),
        reg_file(0),
        reg_referenced{0},
        setvl_count(0),
        vlmax(0),
        vlenb(0),
        vxsat(0),
        vxrm(0),
        vstart(0),
        vl(0),
        vtype(0),
        vma(0),
        vta(0),
        vsew(0),
        vflmul(0),
        ELEN(0),
        VLEN(0),
        vill(false),
        vstart_alu(false) {
      }

      ~vectorUnit_t(){
        free(reg_file);
        reg_file = 0;
      }

      reg_t set_vl(int rd, int rs1, reg_t reqVL, reg_t newType);

      reg_t get_vlen() { return VLEN; }
      reg_t get_elen() { return ELEN; }
      reg_t get_slen() { return VLEN; }

      VRM get_vround_mode() {
        return (VRM)(vxrm->read());
      }
  };

  vectorUnit_t VU;
};

/*regfile_cap_t operations impl*/
/*rc_update is default to be true*/
// read an integer
template <class T, size_t N, bool zero_reg>
const T&
regfile_cap_t<T, N, zero_reg>::operator [] (size_t i)
{
  if (i == 0 && zero_reg) {
    return data[0];
  }

  // in normal world, zero will be read if use a cap reg as an integer operand
  if (p->is_secure_world()) {
    assert(is_data(i)); // FIXME: throw exception
  }
  else{
    // delayed zeroing (read before write)
    if (is_cap(i)) memset(data + i, 0, sizeof(data[i]));
  }
  
  return data[i];
}

// read a capability
template <class T, size_t N, bool zero_reg>
cap64_t&
regfile_cap_t<T, N, zero_reg>::read_cap(size_t i)
{
  if (i == 0 && zero_reg) {
    return cap_data[0].cap;
  }
  assert(is_cap(i)); // FIXME: throw exception
  return cap_data[i].cap;
}

// write an integer
template <class T, size_t N, bool zero_reg>
void
regfile_cap_t<T, N, zero_reg>::write(size_t i, T value, bool rc_update/*=true*/)
{
  if (!zero_reg || i != 0){
    data[i] = value;
    if (is_cap(i)) {
      if(rc_update) p->updateRC(cap_data[i].cap.node_id, -1);
      cap_data[i].set_data();
    }
  }
}

// write a capability
// return value: cap_is_linear; manually remove source if linear after write
template <class T, size_t N, bool zero_reg>
bool
regfile_cap_t<T, N, zero_reg>::write_cap(size_t i, const cap64_t &cap, bool rc_update/*=true*/)
{
  if (!zero_reg || i != 0){
    if (rc_update && is_cap(i)) p->updateRC(cap_data[i].cap.node_id, -1);
    cap_data[i].set_cap(cap);
    if (rc_update && cap.is_linear() == false) p->updateRC(cap.node_id, 1);
    return cap.is_linear();
  }
  return false;
}

// move a capability
template <class T, size_t N, bool zero_reg>
void
regfile_cap_t<T, N, zero_reg>::move(size_t to, size_t from)
{
  if (from == to) return;
  assert(is_cap(from)); // FIXME: throw exception

  if (write_cap(to, cap_data[from].cap)) {
    reset_i(from);
  }
}

// FIXME
template <class T, size_t N, bool zero_reg>
void
regfile_cap_t<T, N, zero_reg>::split_cap(size_t reg, size_t split_reg, reg_t pv, rev_node_id_t split_node_id) {
  assert(split_node_id != REV_NODE_ID_INVALID);
  if (is_cap(split_reg)) p->updateRC(cap_data[split_reg].cap.node_id, -1);
  cap_data[split_reg] = cap_data[reg];
  cap_data[split_reg].cap.node_id = split_node_id;
  cap_data[reg].cap.end = pv;
  cap_data[split_reg].cap.base = pv;
}
// FIXME
template <class T, size_t N, bool zero_reg>
void
regfile_cap_t<T, N, zero_reg>::delin(size_t reg) {
  assert(cap_data[reg].cap.type == CAP_TYPE_LINEAR);
  cap_data[reg].cap.type = CAP_TYPE_NONLINEAR;
  p->set_nonlinear(cap_data[reg].cap.node_id);
}
// FIXME
template <class T, size_t N, bool zero_reg>
void
regfile_cap_t<T, N, zero_reg>::mrev(size_t reg, size_t cap_reg, rev_node_id_t new_node_id) {
  assert(new_node_id != REV_NODE_ID_INVALID);
  if (is_cap(reg)) p->updateRC(cap_data[reg].cap.node_id, -1);
  cap_data[reg] = cap_data[cap_reg];
  cap_data[cap_reg].cap.node_id = new_node_id;
  cap_data[reg].cap.type = CAP_TYPE_REVOCATION;
}

#endif
