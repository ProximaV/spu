#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace spu {

class SpuMemory;
class ChannelRouter;

// Architectural CBEA + PS3 Isolation channel IDs
enum ChannelId : uint8_t {
    CH_SPU_RdEventStat    = 0,
    CH_SPU_WrEventMask    = 1,
    CH_SPU_WrEventAck     = 2,
    CH_SPU_RdSigNotify1   = 3,
    CH_SPU_RdSigNotify2   = 4,
    CH_SPU_WrDec          = 7,
    CH_SPU_RdDec          = 8,
    CH_SPU_RdEventMask    = 11,
    CH_SPU_RdMachStat     = 13,
    CH_SPU_WrSRR0         = 14,
    CH_SPU_RdSRR0         = 15,
    CH_MFC_WrMSSyncReq    = 9,
    CH_MFC_RdTagMask      = 12,
    CH_MFC_LSA            = 16,
    CH_MFC_EAH            = 17,
    CH_MFC_EAL            = 18,
    CH_MFC_Size           = 19,
    CH_MFC_TagID          = 20,
    CH_MFC_Cmd            = 21,
    CH_MFC_WrTagMask      = 22,
    CH_MFC_WrTagUpdate    = 23,
    CH_MFC_RdTagStat      = 24,
    CH_MFC_RdListStallStat= 25,
    CH_MFC_WrListStallAck = 26,
    CH_MFC_RdAtomicStat   = 27,
    CH_SPU_WrOutMbox      = 28,
    CH_SPU_RdInMbox       = 29,
    CH_SPU_WrOutIntrMbox  = 30,
    CH_PS3_ISO_64         = 64,
    CH_PS3_ISO_65         = 65,
    CH_PS3_ISO_66         = 66,
    CH_PS3_ISO_67         = 67,
    CH_PS3_ISO_68         = 68,
};

// SPU Event Status bit definitions (CBEA)
enum SpuEventBits : uint32_t {
    EVT_MFC_TAG_STATUS_UPDATE = 1u << 0,
    EVT_MFC_LIST_STALL        = 1u << 1,
    EVT_MFC_CMD_QUEUE_AVAIL   = 1u << 3,
    EVT_SPU_IN_MBOX_AVAIL     = 1u << 4,
    EVT_SPU_DECREMENTER       = 1u << 5,
    EVT_SPU_OUT_INTR_MBOX     = 1u << 6,
    EVT_SPU_OUT_MBOX          = 1u << 7,
    EVT_MFC_DMA_SN_RESERVATION= 1u << 8,
    EVT_SIG_NOTIFY_2          = 1u << 9,
    EVT_SIG_NOTIFY_1          = 1u << 10,
    EVT_LOCK_LINE_LOST        = 1u << 11,
    EVT_MULTISOURCE_SYNC      = 1u << 12,
};

const char *ChannelSymbolicName(uint8_t ch);
bool ParseChannelId(const std::string &token, uint8_t *out_ch);

enum class ChannelStatus : uint8_t {
    Ok = 0,       // Transfer completed immediately
    Stalled,      // Channel empty/full: PC stays on rdch/wrch (CPU stalls)
    Break,        // Pause debugger immediately (break-on-read/write/empty)
};

enum class EmptyPolicy : uint8_t {
    Zero = 0,     // Return 0 immediately
    RepeatLast,   // Repeat last read value
    Stall,        // Stall CPU (keep PC on rdch) until data pushed
    Break,        // Trigger debugger break on empty read (PC stays on rdch so user can push & resume)
    Prompt,       // Invoke interactive UI prompt callback (falls back to Break if no prompt callback)
};

struct ChannelReadResult {
    ChannelStatus status = ChannelStatus::Ok;
    uint32_t value = 0;
    std::string reason;
};

struct ChannelWriteResult {
    ChannelStatus status = ChannelStatus::Ok;
    std::string reason;
};

struct ChannelLogEntry {
    uint64_t cycle = 0;
    uint32_t pc = 0;
    uint8_t ch = 0;
    char op = 'R';  // 'R'=rdch, 'W'=wrch, 'C'=rchcnt
    uint32_t value = 0;
    ChannelStatus status = ChannelStatus::Ok;
    std::string note;
};

// ---------------------------------------------------------------------------
// Pluggable Channel Device Interface
// ---------------------------------------------------------------------------
class ISpuChannelDevice {
public:
    virtual ~ISpuChannelDevice() = default;

    virtual std::string Name() const = 0;
    virtual std::string TypeName() const = 0;
    virtual void Reset() = 0;

    virtual ChannelReadResult Read(uint8_t ch, ChannelRouter &router) = 0;
    virtual ChannelWriteResult Write(uint8_t ch, uint32_t val, ChannelRouter &router) = 0;
    virtual uint32_t ReadCount(uint8_t ch, ChannelRouter &router) = 0;
    virtual void OnTick(uint64_t delta_cycles, ChannelRouter &router) {
        (void)delta_cycles;
        (void)router;
    }

    // Optional manual manipulation helpers (used by CLI & IDC)
    virtual bool PushInput(uint8_t ch, uint32_t val) { (void)ch; (void)val; return false; }
    virtual bool PopOutput(uint8_t ch, uint32_t *out) { (void)ch; (void)out; return false; }
    virtual bool SetValue(uint8_t ch, uint32_t val) { (void)ch; (void)val; return false; }
    virtual bool SetCount(uint8_t ch, uint32_t cnt) { (void)ch; (void)cnt; return false; }
    virtual std::string Describe(uint8_t ch) const = 0;
};

// ---------------------------------------------------------------------------
// 1. User Device: FifoChannelDevice (preloaded RX queue + captured TX queue)
// ---------------------------------------------------------------------------
class FifoChannelDevice final : public ISpuChannelDevice {
public:
    explicit FifoChannelDevice(std::string name = "fifo",
                               EmptyPolicy on_empty = EmptyPolicy::Break,
                               uint32_t default_val = 0,
                               size_t max_depth = 1024);

    std::string Name() const override { return name_; }
    std::string TypeName() const override { return "fifo"; }
    void Reset() override;

    ChannelReadResult Read(uint8_t ch, ChannelRouter &router) override;
    ChannelWriteResult Write(uint8_t ch, uint32_t val, ChannelRouter &router) override;
    uint32_t ReadCount(uint8_t ch, ChannelRouter &router) override;

    bool PushInput(uint8_t ch, uint32_t val) override;
    bool PopOutput(uint8_t ch, uint32_t *out) override;
    bool SetCount(uint8_t ch, uint32_t cnt) override;
    std::string Describe(uint8_t ch) const override;

    void SetEmptyPolicy(EmptyPolicy p) { on_empty_ = p; }
    EmptyPolicy GetEmptyPolicy() const { return on_empty_; }
    void SetInitialRx(const std::vector<uint32_t> &vals);
    const std::deque<uint32_t> &RxQueue() const { return rx_; }
    const std::deque<uint32_t> &TxQueue() const { return tx_; }

private:
    std::string name_;
    EmptyPolicy on_empty_ = EmptyPolicy::Break;
    uint32_t default_val_ = 0;
    uint32_t last_read_ = 0;
    size_t max_depth_ = 1024;
    bool has_count_override_ = false;
    uint32_t count_override_ = 0;
    std::vector<uint32_t> initial_rx_;
    std::deque<uint32_t> rx_;
    std::deque<uint32_t> tx_;
};

// ---------------------------------------------------------------------------
// 2. User Device: RegisterChannelDevice (stateful 32-bit word register)
// ---------------------------------------------------------------------------
class RegisterChannelDevice final : public ISpuChannelDevice {
public:
    explicit RegisterChannelDevice(std::string name = "register",
                                   uint32_t initial_val = 0,
                                   uint32_t count = 1,
                                   bool read_only = false,
                                   bool clear_on_read = false);

    std::string Name() const override { return name_; }
    std::string TypeName() const override { return "register"; }
    void Reset() override;

    ChannelReadResult Read(uint8_t ch, ChannelRouter &router) override;
    ChannelWriteResult Write(uint8_t ch, uint32_t val, ChannelRouter &router) override;
    uint32_t ReadCount(uint8_t ch, ChannelRouter &router) override;

    bool PushInput(uint8_t ch, uint32_t val) override;
    bool PopOutput(uint8_t ch, uint32_t *out) override;
    bool SetValue(uint8_t ch, uint32_t val) override;
    bool SetCount(uint8_t ch, uint32_t cnt) override;
    std::string Describe(uint8_t ch) const override;

    uint32_t Value() const { return value_; }

private:
    std::string name_;
    uint32_t initial_val_ = 0;
    uint32_t value_ = 0;
    uint32_t count_ = 1;
    bool read_only_ = false;
    bool clear_on_read_ = false;
};

// ---------------------------------------------------------------------------
// 3. User Device: ResponderChannelDevice (pattern-match write -> reply + event)
// ---------------------------------------------------------------------------
struct ResponderRule {
    bool match_any = false;
    uint32_t when_write = 0;
    int reply_channel = -1;  // -1 => push onto same channel
    std::vector<uint32_t> reply_words;
    uint32_t raise_event = 0;
};

class ResponderChannelDevice final : public ISpuChannelDevice {
public:
    explicit ResponderChannelDevice(std::string name = "responder",
                                    EmptyPolicy on_empty = EmptyPolicy::Break);

    std::string Name() const override { return name_; }
    std::string TypeName() const override { return "responder"; }
    void Reset() override;

    void AddRule(const ResponderRule &rule) { rules_.push_back(rule); }
    const std::vector<ResponderRule> &Rules() const { return rules_; }

    ChannelReadResult Read(uint8_t ch, ChannelRouter &router) override;
    ChannelWriteResult Write(uint8_t ch, uint32_t val, ChannelRouter &router) override;
    uint32_t ReadCount(uint8_t ch, ChannelRouter &router) override;

    bool PushInput(uint8_t ch, uint32_t val) override;
    bool PopOutput(uint8_t ch, uint32_t *out) override;
    std::string Describe(uint8_t ch) const override;

private:
    std::string name_;
    EmptyPolicy on_empty_ = EmptyPolicy::Break;
    std::vector<ResponderRule> rules_;
    std::deque<uint32_t> rx_;
    std::deque<uint32_t> tx_;
};

// ---------------------------------------------------------------------------
// 4. User Device: StubLoggerDevice (logs access, returns fixed value & count)
// ---------------------------------------------------------------------------
class StubLoggerDevice final : public ISpuChannelDevice {
public:
    explicit StubLoggerDevice(std::string name = "stub",
                              uint32_t default_read = 0,
                              uint32_t default_count = 1);

    std::string Name() const override { return name_; }
    std::string TypeName() const override { return "stub"; }
    void Reset() override {}

    ChannelReadResult Read(uint8_t ch, ChannelRouter &router) override;
    ChannelWriteResult Write(uint8_t ch, uint32_t val, ChannelRouter &router) override;
    uint32_t ReadCount(uint8_t ch, ChannelRouter &router) override;

    bool SetValue(uint8_t ch, uint32_t val) override { (void)ch; default_read_ = val; return true; }
    bool SetCount(uint8_t ch, uint32_t cnt) override { (void)ch; default_count_ = cnt; return true; }
    std::string Describe(uint8_t ch) const override;

private:
    std::string name_;
    uint32_t default_read_ = 0;
    uint32_t default_count_ = 1;
    uint32_t last_written_ = 0;
    uint64_t reads_ = 0;
    uint64_t writes_ = 0;
};

// ---------------------------------------------------------------------------
// 5. User Device: CallbackChannelDevice (C++ / IDAPython / IDC dynamic handler)
// ---------------------------------------------------------------------------
// op: 'R' (rdch), 'W' (wrch), 'C' (rchcnt)
// For 'R' & 'C', callback writes result into *value_out.
// Returns ChannelStatus (Ok / Stalled / Break).
using ChannelCallbackFn = std::function<ChannelStatus(uint8_t ch, char op, uint32_t in_val, uint32_t *value_out)>;

class CallbackChannelDevice final : public ISpuChannelDevice {
public:
    CallbackChannelDevice(std::string name, ChannelCallbackFn cb);

    std::string Name() const override { return name_; }
    std::string TypeName() const override { return "callback"; }
    void Reset() override {}

    ChannelReadResult Read(uint8_t ch, ChannelRouter &router) override;
    ChannelWriteResult Write(uint8_t ch, uint32_t val, ChannelRouter &router) override;
    uint32_t ReadCount(uint8_t ch, ChannelRouter &router) override;
    std::string Describe(uint8_t ch) const override;

private:
    std::string name_;
    ChannelCallbackFn cb_;
};

// ---------------------------------------------------------------------------
// Built-in Architectural Devices (Event/Decrementer, MFC DMA, Mailboxes, PS3 ISO)
// ---------------------------------------------------------------------------
class EventDecDevice final : public ISpuChannelDevice {
public:
    std::string Name() const override { return "cbea_event_dec"; }
    std::string TypeName() const override { return "event"; }
    void Reset() override;

    ChannelReadResult Read(uint8_t ch, ChannelRouter &router) override;
    ChannelWriteResult Write(uint8_t ch, uint32_t val, ChannelRouter &router) override;
    uint32_t ReadCount(uint8_t ch, ChannelRouter &router) override;
    void OnTick(uint64_t delta_cycles, ChannelRouter &router) override;

    bool PushInput(uint8_t ch, uint32_t val) override;
    bool SetValue(uint8_t ch, uint32_t val) override;
    std::string Describe(uint8_t ch) const override;

    void RaiseEvent(uint32_t bits);
    void ClearEvent(uint32_t bits);
    uint32_t PendingEvents() const { return event_stat_; }
    uint32_t EventMask() const { return event_mask_; }
    bool HasMaskedPendingEvent() const { return (event_stat_ & event_mask_) != 0; }

    uint32_t Decrementer() const { return dec_; }
    void SetDecrementer(uint32_t val) { dec_ = val; dec_running_ = true; }
    uint32_t Srr0() const { return srr0_; }
    void SetSrr0(uint32_t val) { srr0_ = val & 0x3FFFCu; }
    uint32_t MachStat() const { return mach_stat_; }
    void SetInterruptEnable(bool ie);
    bool InterruptEnabled() const { return (mach_stat_ & 1u) != 0; }
    uint32_t SigNotify1() const { return sig1_; }
    uint32_t SigNotify2() const { return sig2_; }

private:
    uint32_t event_stat_ = 0;
    uint32_t event_mask_ = 0;
    uint32_t sig1_ = 0;
    uint32_t sig2_ = 0;
    bool sig1_valid_ = false;
    bool sig2_valid_ = false;
    uint32_t dec_ = 0;
    bool dec_running_ = false;
    uint32_t mach_stat_ = 0;  // bit 0 = IE
    uint32_t srr0_ = 0;
};

struct MfcDmaRecord {
    uint32_t lsa = 0;
    uint64_t ea = 0;
    uint32_t size = 0;
    uint8_t tag = 0;
    uint16_t cmd = 0;
    bool ok = true;
};

class MfcDevice final : public ISpuChannelDevice {
public:
    explicit MfcDevice(SpuMemory *mem);

    std::string Name() const override { return "cbea_mfc"; }
    std::string TypeName() const override { return "mfc"; }
    void Reset() override;

    ChannelReadResult Read(uint8_t ch, ChannelRouter &router) override;
    ChannelWriteResult Write(uint8_t ch, uint32_t val, ChannelRouter &router) override;
    uint32_t ReadCount(uint8_t ch, ChannelRouter &router) override;
    std::string Describe(uint8_t ch) const override;

    uint32_t Lsa() const { return lsa_; }
    uint32_t Eah() const { return eah_; }
    uint32_t Eal() const { return eal_; }
    uint32_t Size() const { return size_; }
    uint32_t TagId() const { return tag_id_; }
    uint32_t LastCmd() const { return last_cmd_; }
    uint32_t TagMask() const { return tag_mask_; }
    uint32_t TagStatus() const { return tag_stat_; }
    uint32_t AtomicStatus() const { return atomic_stat_; }
    const std::deque<MfcDmaRecord> &History() const { return history_; }

private:
    bool ExecuteDma(uint32_t cmd, ChannelRouter &router);
    bool ExecuteDmaList(uint32_t cmd, bool is_get, ChannelRouter &router);

    SpuMemory *mem_ = nullptr;
    uint32_t lsa_ = 0;
    uint32_t eah_ = 0;
    uint32_t eal_ = 0;
    uint32_t size_ = 0;
    uint32_t tag_id_ = 0;
    uint32_t last_cmd_ = 0;
    uint32_t tag_mask_ = 0;
    uint32_t tag_stat_ = 0;
    uint32_t tag_update_pending_ = 0;
    uint32_t list_stall_stat_ = 0;
    uint32_t atomic_stat_ = 0;
    uint32_t atomic_stat_valid_ = 0;
    std::deque<MfcDmaRecord> history_;
};

class MailboxDevice final : public ISpuChannelDevice {
public:
    std::string Name() const override { return "cbea_mailbox"; }
    std::string TypeName() const override { return "mailbox"; }
    void Reset() override;

    ChannelReadResult Read(uint8_t ch, ChannelRouter &router) override;
    ChannelWriteResult Write(uint8_t ch, uint32_t val, ChannelRouter &router) override;
    uint32_t ReadCount(uint8_t ch, ChannelRouter &router) override;

    bool PushInput(uint8_t ch, uint32_t val) override;
    bool PopOutput(uint8_t ch, uint32_t *out) override;
    std::string Describe(uint8_t ch) const override;

    const std::deque<uint32_t> &InMbox() const { return in_mbox_; }
    const std::deque<uint32_t> &OutMbox() const { return out_mbox_; }
    const std::deque<uint32_t> &OutIntrMbox() const { return out_intr_mbox_; }
    void SetInMboxEmptyPolicy(EmptyPolicy p) { in_empty_policy_ = p; }

private:
    std::deque<uint32_t> in_mbox_;
    std::deque<uint32_t> out_mbox_;
    std::deque<uint32_t> out_intr_mbox_;
    EmptyPolicy in_empty_policy_ = EmptyPolicy::Break;
};

// ---------------------------------------------------------------------------
// ChannelRouter: owns 0..127 routing, break/prompt policies, JSON config, log
// ---------------------------------------------------------------------------
struct ChannelBreakFlags {
    bool break_on_read = false;
    bool break_on_write = false;
    bool prompt_on_empty = false;
};

// Optional UI interactive prompt callback (e.g. IDA ask_str). Returns true if user supplied *val_out.
using ChannelPromptFn = std::function<bool(uint8_t ch, uint32_t pc, uint32_t *val_out)>;

class ChannelRouter {
public:
    explicit ChannelRouter(SpuMemory *mem);

    void ResetToDefaults();
    void ResetState();  // Reset device queues/registers while preserving attached devices

    // Core CPU channel instructions
    ChannelReadResult ReadChannel(uint8_t ch, uint32_t pc, uint64_t cycle);
    ChannelWriteResult WriteChannel(uint8_t ch, uint32_t val, uint32_t pc, uint64_t cycle);
    uint32_t ReadChannelCount(uint8_t ch, uint32_t pc, uint64_t cycle);
    void Tick(uint64_t delta_cycles);

    // Device management
    void AttachDevice(uint8_t ch, std::shared_ptr<ISpuChannelDevice> dev);
    void DetachDevice(uint8_t ch);
    std::shared_ptr<ISpuChannelDevice> GetDevice(uint8_t ch) const;

    // Built-in architectural device accessors
    EventDecDevice &Events() { return *events_; }
    const EventDecDevice &Events() const { return *events_; }
    MfcDevice &Mfc() { return *mfc_; }
    const MfcDevice &Mfc() const { return *mfc_; }
    MailboxDevice &Mailbox() { return *mailbox_; }
    const MailboxDevice &Mailbox() const { return *mailbox_; }
    SpuMemory *Memory() const { return mem_; }

    // Manual data injection / inspection (used by CLI & IDC)
    bool PushInput(uint8_t ch, uint32_t val);
    bool PopOutput(uint8_t ch, uint32_t *out);
    bool SetValue(uint8_t ch, uint32_t val);
    bool SetCount(uint8_t ch, uint32_t cnt);

    // Debugger break/prompt controls
    void SetBreakOnRead(uint8_t ch, bool enable) { flags_[ch & 0x7Fu].break_on_read = enable; }
    void SetBreakOnWrite(uint8_t ch, bool enable) { flags_[ch & 0x7Fu].break_on_write = enable; }
    void SetPromptOnEmpty(uint8_t ch, bool enable) { flags_[ch & 0x7Fu].prompt_on_empty = enable; }
    ChannelBreakFlags GetBreakFlags(uint8_t ch) const { return flags_[ch & 0x7Fu]; }
    void SetPromptCallback(ChannelPromptFn fn) { prompt_cb_ = std::move(fn); }
    bool TryInteractivePrompt(uint8_t ch, uint32_t *val_out) const;

    // Transaction log
    const std::deque<ChannelLogEntry> &Log() const { return log_; }
    void ClearLog() { log_.clear(); }

    // JSON Configuration Loader & Exporter
    bool LoadConfigFile(const std::string &path, std::string *err_out = nullptr);
    bool LoadConfigJson(const std::string &json_text, const std::string &base_dir = "",
                        std::string *err_out = nullptr);
    bool SaveConfigFile(const std::string &path, std::string *err_out = nullptr) const;
    std::string ExportConfigJson() const;

    std::string FormatSummary() const;

private:
    void RecordLog(uint64_t cycle, uint32_t pc, uint8_t ch, char op, uint32_t val,
                   ChannelStatus status, const std::string &note = "");

    SpuMemory *mem_ = nullptr;
    std::shared_ptr<EventDecDevice> events_;
    std::shared_ptr<MfcDevice> mfc_;
    std::shared_ptr<MailboxDevice> mailbox_;
    std::shared_ptr<StubLoggerDevice> default_stub_;

    std::array<std::shared_ptr<ISpuChannelDevice>, 128> slots_;
    std::array<ChannelBreakFlags, 128> flags_{};
    ChannelPromptFn prompt_cb_;
    uint32_t cur_pc_ = 0;
    std::deque<ChannelLogEntry> log_;
};

}  // namespace spu
