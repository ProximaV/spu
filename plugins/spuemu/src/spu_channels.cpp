#include "spu_channels.h"

#include "log.h"
#include "memory.h"
#include "module_path.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>

namespace spu {

namespace {

struct ChannelNameEntry {
    uint8_t id;
    const char *name;
};

constexpr ChannelNameEntry kChannelNames[] = {
    { 0,  "SPU_RdEventStat" },
    { 1,  "SPU_WrEventMask" },
    { 2,  "SPU_WrEventAck" },
    { 3,  "SPU_RdSigNotify1" },
    { 4,  "SPU_RdSigNotify2" },
    { 7,  "SPU_WrDec" },
    { 8,  "SPU_RdDec" },
    { 9,  "MFC_WrMSSyncReq" },
    { 11, "SPU_RdEventMask" },
    { 12, "MFC_RdTagMask" },
    { 13, "SPU_RdMachStat" },
    { 14, "SPU_WrSRR0" },
    { 15, "SPU_RdSRR0" },
    { 16, "MFC_LSA" },
    { 17, "MFC_EAH" },
    { 18, "MFC_EAL" },
    { 19, "MFC_Size" },
    { 20, "MFC_TagID" },
    { 21, "MFC_Cmd" },
    { 22, "MFC_WrTagMask" },
    { 23, "MFC_WrTagUpdate" },
    { 24, "MFC_RdTagStat" },
    { 25, "MFC_RdListStallStat" },
    { 26, "MFC_WrListStallAck" },
    { 27, "MFC_RdAtomicStat" },
    { 28, "SPU_WrOutMbox" },
    { 29, "SPU_RdInMbox" },
    { 30, "SPU_WrOutIntrMbox" },
    { 64, "SPU_IsoCntl" },
    { 65, "SPU_IsoStat" },
    { 66, "SPU_IsoRootKey" },
    { 67, "SPU_IsoKey" },
    { 68, "SPU_IsoIdent" },
};

bool StrIEq(const std::string &a, const char *b) {
    size_t i = 0;
    for (; i < a.size() && b[i] != '\0'; ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return i == a.size() && b[i] == '\0';
}

EmptyPolicy ParseEmptyPolicy(const std::string &s, EmptyPolicy fallback = EmptyPolicy::Break) {
    if (StrIEq(s, "zero")) return EmptyPolicy::Zero;
    if (StrIEq(s, "repeat") || StrIEq(s, "repeat_last")) return EmptyPolicy::RepeatLast;
    if (StrIEq(s, "stall")) return EmptyPolicy::Stall;
    if (StrIEq(s, "break")) return EmptyPolicy::Break;
    if (StrIEq(s, "prompt")) return EmptyPolicy::Prompt;
    return fallback;
}

const char *EmptyPolicyName(EmptyPolicy p) {
    switch (p) {
    case EmptyPolicy::Zero:       return "zero";
    case EmptyPolicy::RepeatLast: return "repeat_last";
    case EmptyPolicy::Stall:      return "stall";
    case EmptyPolicy::Break:      return "break";
    case EmptyPolicy::Prompt:     return "prompt";
    }
    return "break";
}

bool ParseHexOrDecU64(const std::string &s, uint64_t *out) {
    if (s.empty() || !out) return false;
    char *end = nullptr;
    const unsigned long long v = std::strtoull(s.c_str(), &end, 0);
    if (!end || *end != '\0') return false;
    *out = static_cast<uint64_t>(v);
    return true;
}

// ---------------------------------------------------------------------------
// Minimal, self-contained JSON DOM parser (no external dependencies)
// ---------------------------------------------------------------------------
struct JsonValue {
    enum Type { Null, Bool, Number, String, Array, Object };
    Type type = Null;
    bool bval = false;
    int64_t ival = 0;
    uint64_t uval = 0;
    std::string sval;
    std::vector<JsonValue> arr;
    std::map<std::string, JsonValue> obj;

    bool IsObject() const { return type == Object; }
    bool IsArray()  const { return type == Array; }
    bool IsString() const { return type == String; }
    bool IsNumber() const { return type == Number; }
    bool IsBool()   const { return type == Bool; }

    const JsonValue *Get(const std::string &k) const {
        if (type != Object) return nullptr;
        auto it = obj.find(k);
        return it == obj.end() ? nullptr : &it->second;
    }

    uint64_t AsU64(uint64_t def = 0) const {
        if (type == Number) return uval;
        if (type == String) {
            uint64_t v = def;
            if (ParseHexOrDecU64(sval, &v)) return v;
        }
        return def;
    }

    uint32_t AsU32(uint32_t def = 0) const {
        return static_cast<uint32_t>(AsU64(def));
    }

    bool AsBool(bool def = false) const {
        if (type == Bool) return bval;
        if (type == Number) return uval != 0;
        return def;
    }

    std::string AsString(const std::string &def = "") const {
        return (type == String) ? sval : def;
    }
};

class JsonParser {
public:
    explicit JsonParser(const std::string &src) : s_(src) {}

    bool Parse(JsonValue *out, std::string *err) {
        SkipWs();
        if (!ParseValue(out, err)) return false;
        SkipWs();
        if (pos_ != s_.size()) {
            if (err) *err = "Unexpected trailing characters in JSON";
            return false;
        }
        return true;
    }

private:
    void SkipWs() {
        while (pos_ < s_.size()) {
            const char c = s_[pos_];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                ++pos_;
            } else if (c == '/' && pos_ + 1 < s_.size() && s_[pos_ + 1] == '/') {
                // Allow // comments in device config JSON for user convenience
                pos_ += 2;
                while (pos_ < s_.size() && s_[pos_] != '\n') ++pos_;
            } else {
                break;
            }
        }
    }

    bool ParseValue(JsonValue *out, std::string *err) {
        SkipWs();
        if (pos_ >= s_.size()) {
            if (err) *err = "Unexpected end of JSON";
            return false;
        }
        const char c = s_[pos_];
        if (c == '{') return ParseObject(out, err);
        if (c == '[') return ParseArray(out, err);
        if (c == '"') {
            out->type = JsonValue::String;
            return ParseString(&out->sval, err);
        }
        if (c == 't' && s_.compare(pos_, 4, "true") == 0) {
            pos_ += 4;
            out->type = JsonValue::Bool;
            out->bval = true;
            return true;
        }
        if (c == 'f' && s_.compare(pos_, 5, "false") == 0) {
            pos_ += 5;
            out->type = JsonValue::Bool;
            out->bval = false;
            return true;
        }
        if (c == 'n' && s_.compare(pos_, 4, "null") == 0) {
            pos_ += 4;
            out->type = JsonValue::Null;
            return true;
        }
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) {
            return ParseNumber(out, err);
        }
        if (err) *err = std::string("Unexpected token '") + c + "' in JSON";
        return false;
    }

    bool ParseString(std::string *out, std::string *err) {
        if (pos_ >= s_.size() || s_[pos_] != '"') {
            if (err) *err = "Expected '\"'";
            return false;
        }
        ++pos_;
        out->clear();
        while (pos_ < s_.size()) {
            const char c = s_[pos_++];
            if (c == '"') return true;
            if (c == '\\') {
                if (pos_ >= s_.size()) break;
                const char e = s_[pos_++];
                switch (e) {
                case '"':  out->push_back('"'); break;
                case '\\': out->push_back('\\'); break;
                case '/':  out->push_back('/'); break;
                case 'b':  out->push_back('\b'); break;
                case 'f':  out->push_back('\f'); break;
                case 'n':  out->push_back('\n'); break;
                case 'r':  out->push_back('\r'); break;
                case 't':  out->push_back('\t'); break;
                default:   out->push_back(e); break;
                }
            } else {
                out->push_back(c);
            }
        }
        if (err) *err = "Unterminated string literal";
        return false;
    }

    bool ParseNumber(JsonValue *out, std::string *err) {
        const size_t start = pos_;
        if (s_[pos_] == '-') ++pos_;
        if (pos_ + 1 < s_.size() && s_[pos_] == '0' && (s_[pos_ + 1] == 'x' || s_[pos_ + 1] == 'X')) {
            pos_ += 2;
            while (pos_ < s_.size() && std::isxdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
        } else {
            while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
            if (pos_ < s_.size() && s_[pos_] == '.') {
                ++pos_;
                while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) ++pos_;
            }
        }
        const std::string tok = s_.substr(start, pos_ - start);
        out->type = JsonValue::Number;
        if (!tok.empty() && tok[0] == '-') {
            out->ival = std::strtoll(tok.c_str(), nullptr, 0);
            out->uval = static_cast<uint64_t>(out->ival);
        } else {
            out->uval = std::strtoull(tok.c_str(), nullptr, 0);
            out->ival = static_cast<int64_t>(out->uval);
        }
        (void)err;
        return true;
    }

    bool ParseArray(JsonValue *out, std::string *err) {
        ++pos_;  // '['
        out->type = JsonValue::Array;
        out->arr.clear();
        SkipWs();
        if (pos_ < s_.size() && s_[pos_] == ']') {
            ++pos_;
            return true;
        }
        while (pos_ < s_.size()) {
            JsonValue elem;
            if (!ParseValue(&elem, err)) return false;
            out->arr.push_back(std::move(elem));
            SkipWs();
            if (pos_ < s_.size() && s_[pos_] == ',') {
                ++pos_;
                SkipWs();
                if (pos_ < s_.size() && s_[pos_] == ']') { ++pos_; return true; }  // tolerate trailing comma
                continue;
            }
            if (pos_ < s_.size() && s_[pos_] == ']') {
                ++pos_;
                return true;
            }
            if (err) *err = "Expected ',' or ']' in array";
            return false;
        }
        if (err) *err = "Unterminated JSON array";
        return false;
    }

    bool ParseObject(JsonValue *out, std::string *err) {
        ++pos_;  // '{'
        out->type = JsonValue::Object;
        out->obj.clear();
        SkipWs();
        if (pos_ < s_.size() && s_[pos_] == '}') {
            ++pos_;
            return true;
        }
        while (pos_ < s_.size()) {
            SkipWs();
            std::string key;
            if (!ParseString(&key, err)) return false;
            SkipWs();
            if (pos_ >= s_.size() || s_[pos_] != ':') {
                if (err) *err = "Expected ':' after object key '" + key + "'";
                return false;
            }
            ++pos_;
            JsonValue val;
            if (!ParseValue(&val, err)) return false;
            out->obj[key] = std::move(val);
            SkipWs();
            if (pos_ < s_.size() && s_[pos_] == ',') {
                ++pos_;
                SkipWs();
                if (pos_ < s_.size() && s_[pos_] == '}') { ++pos_; return true; }  // tolerate trailing comma
                continue;
            }
            if (pos_ < s_.size() && s_[pos_] == '}') {
                ++pos_;
                return true;
            }
            if (err) *err = "Expected ',' or '}' in object";
            return false;
        }
        if (err) *err = "Unterminated JSON object";
        return false;
    }

    const std::string &s_;
    size_t pos_ = 0;
};

bool DecodeHexBytes(const std::string &hex, std::vector<uint8_t> *out) {
    out->clear();
    std::string clean;
    clean.reserve(hex.size());
    for (char c : hex) {
        if (std::isxdigit(static_cast<unsigned char>(c))) clean.push_back(c);
    }
    if (clean.size() % 2 != 0) return false;
    out->reserve(clean.size() / 2);
    for (size_t i = 0; i < clean.size(); i += 2) {
        char buf[3] = { clean[i], clean[i + 1], '\0' };
        out->push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
    }
    return true;
}

std::string EscapeJson(const std::string &s) {
    std::string r;
    r.reserve(s.size() + 4);
    for (char c : s) {
        if (c == '\\') r += "\\\\";
        else if (c == '"') r += "\\\"";
        else if (c == '\n') r += "\\n";
        else r.push_back(c);
    }
    return r;
}

}  // namespace

// ---------------------------------------------------------------------------
// Channel Name Utilities
// ---------------------------------------------------------------------------
const char *ChannelSymbolicName(uint8_t ch) {
    for (const auto &e : kChannelNames) {
        if (e.id == ch) return e.name;
    }
    return nullptr;
}

bool ParseChannelId(const std::string &token, uint8_t *out_ch) {
    if (token.empty() || !out_ch) return false;
    // Strip optional leading '$'
    std::string t = token;
    if (!t.empty() && t[0] == '$') t.erase(t.begin());

    // Exact symbolic name match (case-insensitive)
    for (const auto &e : kChannelNames) {
        if (StrIEq(t, e.name)) {
            *out_ch = e.id;
            return true;
        }
    }
    // "chN" prefix
    if (t.size() >= 3 && (t[0] == 'c' || t[0] == 'C') && (t[1] == 'h' || t[1] == 'H')) {
        t = t.substr(2);
    }
    uint64_t val = 0;
    if (ParseHexOrDecU64(t, &val) && val < 128u) {
        *out_ch = static_cast<uint8_t>(val);
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// 1. FifoChannelDevice
// ---------------------------------------------------------------------------
FifoChannelDevice::FifoChannelDevice(std::string name, EmptyPolicy on_empty,
                                     uint32_t default_val, size_t max_depth)
    : name_(std::move(name)),
      on_empty_(on_empty),
      default_val_(default_val),
      max_depth_(max_depth) {}

void FifoChannelDevice::Reset() {
    rx_.clear();
    for (uint32_t v : initial_rx_) rx_.push_back(v);
    tx_.clear();
    last_read_ = default_val_;
    has_count_override_ = false;
}

void FifoChannelDevice::SetInitialRx(const std::vector<uint32_t> &vals) {
    initial_rx_ = vals;
    rx_.clear();
    for (uint32_t v : vals) rx_.push_back(v);
}

ChannelReadResult FifoChannelDevice::Read(uint8_t ch, ChannelRouter &router) {
    if (!rx_.empty()) {
        const uint32_t v = rx_.front();
        rx_.pop_front();
        last_read_ = v;
        return { ChannelStatus::Ok, v, "" };
    }

    const EmptyPolicy policy = router.GetBreakFlags(ch).prompt_on_empty
                                   ? EmptyPolicy::Prompt
                                   : on_empty_;
    switch (policy) {
    case EmptyPolicy::Zero:
        return { ChannelStatus::Ok, default_val_, "empty->default" };
    case EmptyPolicy::RepeatLast:
        return { ChannelStatus::Ok, last_read_, "empty->repeat" };
    case EmptyPolicy::Stall:
        return { ChannelStatus::Stalled, 0, "FIFO empty (stalled)" };
    case EmptyPolicy::Prompt: {
        uint32_t injected = 0;
        if (router.TryInteractivePrompt(ch, &injected)) {
            last_read_ = injected;
            return { ChannelStatus::Ok, injected, "interactive_prompt" };
        }
        return { ChannelStatus::Break, 0, "FIFO empty (prompt cancelled / break)" };
    }
    case EmptyPolicy::Break:
    default:
        return { ChannelStatus::Break, 0, "FIFO empty (break)" };
    }
}

ChannelWriteResult FifoChannelDevice::Write(uint8_t ch, uint32_t val, ChannelRouter &router) {
    (void)ch;
    (void)router;
    if (tx_.size() >= max_depth_) tx_.pop_front();
    tx_.push_back(val);
    return { ChannelStatus::Ok, "" };
}

uint32_t FifoChannelDevice::ReadCount(uint8_t ch, ChannelRouter &router) {
    (void)ch;
    (void)router;
    if (has_count_override_) return count_override_;
    return static_cast<uint32_t>(rx_.size());
}

bool FifoChannelDevice::PushInput(uint8_t ch, uint32_t val) {
    (void)ch;
    if (rx_.size() >= max_depth_) return false;
    rx_.push_back(val);
    return true;
}

bool FifoChannelDevice::PopOutput(uint8_t ch, uint32_t *out) {
    (void)ch;
    if (tx_.empty()) return false;
    if (out) *out = tx_.front();
    tx_.pop_front();
    return true;
}

bool FifoChannelDevice::SetCount(uint8_t ch, uint32_t cnt) {
    (void)ch;
    has_count_override_ = true;
    count_override_ = cnt;
    return true;
}

std::string FifoChannelDevice::Describe(uint8_t ch) const {
    (void)ch;
    std::ostringstream oss;
    oss << "fifo(" << name_ << ") rx=" << rx_.size() << " tx=" << tx_.size()
        << " on_empty=" << EmptyPolicyName(on_empty_);
    return oss.str();
}

// ---------------------------------------------------------------------------
// 2. RegisterChannelDevice
// ---------------------------------------------------------------------------
RegisterChannelDevice::RegisterChannelDevice(std::string name, uint32_t initial_val,
                                             uint32_t count, bool read_only,
                                             bool clear_on_read)
    : name_(std::move(name)),
      initial_val_(initial_val),
      value_(initial_val),
      count_(count),
      read_only_(read_only),
      clear_on_read_(clear_on_read) {}

void RegisterChannelDevice::Reset() {
    value_ = initial_val_;
}

ChannelReadResult RegisterChannelDevice::Read(uint8_t ch, ChannelRouter &router) {
    (void)ch;
    (void)router;
    const uint32_t v = value_;
    if (clear_on_read_) value_ = 0;
    return { ChannelStatus::Ok, v, "" };
}

ChannelWriteResult RegisterChannelDevice::Write(uint8_t ch, uint32_t val, ChannelRouter &router) {
    (void)ch;
    (void)router;
    if (!read_only_) value_ = val;
    return { ChannelStatus::Ok, read_only_ ? "read_only_ignored" : "" };
}

uint32_t RegisterChannelDevice::ReadCount(uint8_t ch, ChannelRouter &router) {
    (void)ch;
    (void)router;
    return count_;
}

bool RegisterChannelDevice::PushInput(uint8_t ch, uint32_t val) {
    (void)ch;
    value_ = val;
    return true;
}

bool RegisterChannelDevice::PopOutput(uint8_t ch, uint32_t *out) {
    (void)ch;
    if (out) *out = value_;
    return true;
}

bool RegisterChannelDevice::SetValue(uint8_t ch, uint32_t val) {
    (void)ch;
    value_ = val;
    return true;
}

bool RegisterChannelDevice::SetCount(uint8_t ch, uint32_t cnt) {
    (void)ch;
    count_ = cnt;
    return true;
}

std::string RegisterChannelDevice::Describe(uint8_t ch) const {
    (void)ch;
    char buf[160];
    std::snprintf(buf, sizeof(buf), "register(%s) val=0x%08X cnt=%u%s%s",
                  name_.c_str(), value_, count_,
                  read_only_ ? " ro" : "",
                  clear_on_read_ ? " clr_on_rd" : "");
    return buf;
}

// ---------------------------------------------------------------------------
// 3. ResponderChannelDevice
// ---------------------------------------------------------------------------
ResponderChannelDevice::ResponderChannelDevice(std::string name, EmptyPolicy on_empty)
    : name_(std::move(name)), on_empty_(on_empty) {}

void ResponderChannelDevice::Reset() {
    rx_.clear();
    tx_.clear();
}

ChannelReadResult ResponderChannelDevice::Read(uint8_t ch, ChannelRouter &router) {
    if (!rx_.empty()) {
        const uint32_t v = rx_.front();
        rx_.pop_front();
        return { ChannelStatus::Ok, v, "" };
    }
    const EmptyPolicy policy = router.GetBreakFlags(ch).prompt_on_empty
                                   ? EmptyPolicy::Prompt
                                   : on_empty_;
    if (policy == EmptyPolicy::Zero) return { ChannelStatus::Ok, 0, "empty->0" };
    if (policy == EmptyPolicy::Stall) return { ChannelStatus::Stalled, 0, "responder empty" };
    if (policy == EmptyPolicy::Prompt) {
        uint32_t v = 0;
        if (router.TryInteractivePrompt(ch, &v)) return { ChannelStatus::Ok, v, "prompt" };
    }
    return { ChannelStatus::Break, 0, "responder RX empty (break)" };
}

ChannelWriteResult ResponderChannelDevice::Write(uint8_t ch, uint32_t val, ChannelRouter &router) {
    tx_.push_back(val);
    if (tx_.size() > 1024) tx_.pop_front();

    const ResponderRule *matched = nullptr;
    for (const auto &r : rules_) {
        if (!r.match_any && r.when_write == val) {
            matched = &r;
            break;
        }
    }
    if (!matched) {
        for (const auto &r : rules_) {
            if (r.match_any) {
                matched = &r;
                break;
            }
        }
    }

    if (matched) {
        const uint8_t target_ch = (matched->reply_channel >= 0 && matched->reply_channel < 128)
                                      ? static_cast<uint8_t>(matched->reply_channel)
                                      : ch;
        for (uint32_t w : matched->reply_words) {
            if (target_ch == ch) {
                rx_.push_back(w);
            } else {
                router.PushInput(target_ch, w);
            }
        }
        if (matched->raise_event != 0) {
            router.Events().RaiseEvent(matched->raise_event);
        }
    }
    return { ChannelStatus::Ok, matched ? "rule_matched" : "no_rule" };
}

uint32_t ResponderChannelDevice::ReadCount(uint8_t ch, ChannelRouter &router) {
    (void)ch;
    (void)router;
    return static_cast<uint32_t>(rx_.size());
}

bool ResponderChannelDevice::PushInput(uint8_t ch, uint32_t val) {
    (void)ch;
    rx_.push_back(val);
    return true;
}

bool ResponderChannelDevice::PopOutput(uint8_t ch, uint32_t *out) {
    (void)ch;
    if (tx_.empty()) return false;
    if (out) *out = tx_.front();
    tx_.pop_front();
    return true;
}

std::string ResponderChannelDevice::Describe(uint8_t ch) const {
    (void)ch;
    std::ostringstream oss;
    oss << "responder(" << name_ << ") rules=" << rules_.size()
        << " rx=" << rx_.size() << " tx=" << tx_.size();
    return oss.str();
}

// ---------------------------------------------------------------------------
// 4. StubLoggerDevice
// ---------------------------------------------------------------------------
StubLoggerDevice::StubLoggerDevice(std::string name, uint32_t default_read, uint32_t default_count)
    : name_(std::move(name)), default_read_(default_read), default_count_(default_count) {}

ChannelReadResult StubLoggerDevice::Read(uint8_t ch, ChannelRouter &router) {
    (void)ch;
    (void)router;
    ++reads_;
    return { ChannelStatus::Ok, default_read_, "stub" };
}

ChannelWriteResult StubLoggerDevice::Write(uint8_t ch, uint32_t val, ChannelRouter &router) {
    (void)ch;
    (void)router;
    last_written_ = val;
    ++writes_;
    return { ChannelStatus::Ok, "stub" };
}

uint32_t StubLoggerDevice::ReadCount(uint8_t ch, ChannelRouter &router) {
    (void)ch;
    (void)router;
    return default_count_;
}

std::string StubLoggerDevice::Describe(uint8_t ch) const {
    (void)ch;
    char buf[160];
    std::snprintf(buf, sizeof(buf), "stub(%s) def_rd=0x%08X def_cnt=%u rd=%llu wr=%llu last_wr=0x%08X",
                  name_.c_str(), default_read_, default_count_,
                  static_cast<unsigned long long>(reads_),
                  static_cast<unsigned long long>(writes_), last_written_);
    return buf;
}

// ---------------------------------------------------------------------------
// 5. CallbackChannelDevice
// ---------------------------------------------------------------------------
CallbackChannelDevice::CallbackChannelDevice(std::string name, ChannelCallbackFn cb)
    : name_(std::move(name)), cb_(std::move(cb)) {}

ChannelReadResult CallbackChannelDevice::Read(uint8_t ch, ChannelRouter &router) {
    (void)router;
    uint32_t v = 0;
    const ChannelStatus st = cb_ ? cb_(ch, 'R', 0, &v) : ChannelStatus::Ok;
    return { st, v, "callback" };
}

ChannelWriteResult CallbackChannelDevice::Write(uint8_t ch, uint32_t val, ChannelRouter &router) {
    (void)router;
    uint32_t dummy = 0;
    const ChannelStatus st = cb_ ? cb_(ch, 'W', val, &dummy) : ChannelStatus::Ok;
    return { st, "callback" };
}

uint32_t CallbackChannelDevice::ReadCount(uint8_t ch, ChannelRouter &router) {
    (void)router;
    uint32_t cnt = 1;
    if (cb_) cb_(ch, 'C', 0, &cnt);
    return cnt;
}

std::string CallbackChannelDevice::Describe(uint8_t ch) const {
    (void)ch;
    return "callback(" + name_ + ")";
}

// ---------------------------------------------------------------------------
// Built-in: EventDecDevice (ch0..ch15)
// ---------------------------------------------------------------------------
void EventDecDevice::Reset() {
    event_stat_ = 0;
    event_mask_ = 0;
    sig1_ = 0;
    sig2_ = 0;
    sig1_valid_ = false;
    sig2_valid_ = false;
    dec_ = 0;
    dec_running_ = false;
    mach_stat_ = 0;
    srr0_ = 0;
}

void EventDecDevice::RaiseEvent(uint32_t bits) {
    event_stat_ |= bits;
}

void EventDecDevice::ClearEvent(uint32_t bits) {
    event_stat_ &= ~bits;
}

void EventDecDevice::SetInterruptEnable(bool ie) {
    if (ie) mach_stat_ |= 1u;
    else mach_stat_ &= ~1u;
}

void EventDecDevice::OnTick(uint64_t delta_cycles, ChannelRouter &router) {
    (void)router;
    if (!dec_running_ || delta_cycles == 0) return;
    const uint32_t prev = dec_;
    const uint32_t step = static_cast<uint32_t>(std::min<uint64_t>(delta_cycles, 0xFFFFFFFFULL));
    dec_ -= step;
    // SPU decrementer fires event when transitioning from positive/zero across 0 to negative (MSB 0->1)
    if ((prev & 0x80000000u) == 0 && (dec_ & 0x80000000u) != 0) {
        event_stat_ |= EVT_SPU_DECREMENTER;
    }
}

ChannelReadResult EventDecDevice::Read(uint8_t ch, ChannelRouter &router) {
    switch (ch) {
    case CH_SPU_RdEventStat: {
        const uint32_t masked = event_stat_ & event_mask_;
        if (masked != 0) {
            return { ChannelStatus::Ok, masked, "" };
        }
        if (router.GetBreakFlags(ch).prompt_on_empty) {
            uint32_t v = 0;
            if (router.TryInteractivePrompt(ch, &v)) return { ChannelStatus::Ok, v, "prompt" };
        }
        return { ChannelStatus::Stalled, 0, "waiting for event" };
    }
    case CH_SPU_RdSigNotify1:
        if (sig1_valid_) {
            const uint32_t v = sig1_;
            sig1_ = 0;
            sig1_valid_ = false;
            return { ChannelStatus::Ok, v, "" };
        }
        return { ChannelStatus::Break, 0, "SigNotify1 empty" };
    case CH_SPU_RdSigNotify2:
        if (sig2_valid_) {
            const uint32_t v = sig2_;
            sig2_ = 0;
            sig2_valid_ = false;
            return { ChannelStatus::Ok, v, "" };
        }
        return { ChannelStatus::Break, 0, "SigNotify2 empty" };
    case CH_SPU_RdDec:
        return { ChannelStatus::Ok, dec_, "" };
    case CH_SPU_RdEventMask:
        return { ChannelStatus::Ok, event_mask_, "" };
    case CH_SPU_RdMachStat:
        return { ChannelStatus::Ok, mach_stat_, "" };
    case CH_SPU_RdSRR0:
        return { ChannelStatus::Ok, srr0_, "" };
    default:
        return { ChannelStatus::Ok, 0, "" };
    }
}

ChannelWriteResult EventDecDevice::Write(uint8_t ch, uint32_t val, ChannelRouter &router) {
    (void)router;
    switch (ch) {
    case CH_SPU_WrEventMask:
        event_mask_ = val;
        break;
    case CH_SPU_WrEventAck:
        event_stat_ &= ~val;
        break;
    case CH_SPU_WrDec:
        dec_ = val;
        dec_running_ = true;
        break;
    case CH_SPU_WrSRR0:
        srr0_ = val & 0x3FFFCu;
        break;
    default:
        break;
    }
    return { ChannelStatus::Ok, "" };
}

uint32_t EventDecDevice::ReadCount(uint8_t ch, ChannelRouter &router) {
    (void)router;
    switch (ch) {
    case CH_SPU_RdEventStat:  return (event_stat_ & event_mask_) != 0 ? 1u : 0u;
    case CH_SPU_RdSigNotify1: return sig1_valid_ ? 1u : 0u;
    case CH_SPU_RdSigNotify2: return sig2_valid_ ? 1u : 0u;
    default:                  return 1u;
    }
}

bool EventDecDevice::PushInput(uint8_t ch, uint32_t val) {
    if (ch == CH_SPU_RdEventStat) {
        event_stat_ |= val;
        return true;
    }
    if (ch == CH_SPU_RdSigNotify1) {
        sig1_ |= val;
        sig1_valid_ = true;
        event_stat_ |= EVT_SIG_NOTIFY_1;
        return true;
    }
    if (ch == CH_SPU_RdSigNotify2) {
        sig2_ |= val;
        sig2_valid_ = true;
        event_stat_ |= EVT_SIG_NOTIFY_2;
        return true;
    }
    return false;
}

bool EventDecDevice::SetValue(uint8_t ch, uint32_t val) {
    switch (ch) {
    case CH_SPU_RdEventStat:  event_stat_ = val; return true;
    case CH_SPU_WrEventMask:
    case CH_SPU_RdEventMask:  event_mask_ = val; return true;
    case CH_SPU_WrDec:
    case CH_SPU_RdDec:        dec_ = val; dec_running_ = true; return true;
    case CH_SPU_RdMachStat:   mach_stat_ = val; return true;
    case CH_SPU_WrSRR0:
    case CH_SPU_RdSRR0:       srr0_ = val & 0x3FFFCu; return true;
    default:                  return PushInput(ch, val);
    }
}

std::string EventDecDevice::Describe(uint8_t ch) const {
    char buf[160];
    switch (ch) {
    case CH_SPU_RdEventStat:
        std::snprintf(buf, sizeof(buf), "event_stat=0x%08X mask=0x%08X", event_stat_, event_mask_);
        break;
    case CH_SPU_WrDec:
    case CH_SPU_RdDec:
        std::snprintf(buf, sizeof(buf), "dec=0x%08X running=%d", dec_, dec_running_ ? 1 : 0);
        break;
    case CH_SPU_RdSRR0:
    case CH_SPU_WrSRR0:
        std::snprintf(buf, sizeof(buf), "SRR0=0x%05X", srr0_);
        break;
    case CH_SPU_RdMachStat:
        std::snprintf(buf, sizeof(buf), "MachStat=0x%08X (IE=%u)", mach_stat_, mach_stat_ & 1u);
        break;
    default:
        std::snprintf(buf, sizeof(buf), "cbea_event_dec(ch%u)", ch);
        break;
    }
    return buf;
}

// ---------------------------------------------------------------------------
// Built-in: MfcDevice (ch9, ch12, ch16..ch27)
// ---------------------------------------------------------------------------
MfcDevice::MfcDevice(SpuMemory *mem) : mem_(mem) {}

void MfcDevice::Reset() {
    lsa_ = 0;
    eah_ = 0;
    eal_ = 0;
    size_ = 0;
    tag_id_ = 0;
    last_cmd_ = 0;
    tag_mask_ = 0;
    tag_stat_ = 0;
    tag_update_pending_ = 0;
    list_stall_stat_ = 0;
    atomic_stat_ = 0;
    atomic_stat_valid_ = 0;
    history_.clear();
}

bool MfcDevice::ExecuteDmaList(uint32_t cmd, bool is_get, ChannelRouter &router) {
    if (!mem_) return false;
    // List sits in Local Store at (eal_ & LSLR & ~7), size_ bytes (each element is 8 bytes: {stall|size, eal})
    const uint32_t list_lsa = eal_ & mem_->Lslr() & ~7u;
    const uint32_t list_bytes = size_ & 0x7FF8u;
    uint32_t cur_lsa = lsa_ & mem_->Lslr();
    bool all_ok = true;

    for (uint32_t off = 0; off < list_bytes; off += 8u) {
        uint8_t elem[8] = {};
        mem_->ReadLs(list_lsa + off, 8u, elem);
        const uint32_t w0 = (static_cast<uint32_t>(elem[0]) << 24) |
                            (static_cast<uint32_t>(elem[1]) << 16) |
                            (static_cast<uint32_t>(elem[2]) << 8) | elem[3];
        const uint32_t w1 = (static_cast<uint32_t>(elem[4]) << 24) |
                            (static_cast<uint32_t>(elem[5]) << 16) |
                            (static_cast<uint32_t>(elem[6]) << 8) | elem[7];
        const bool stall_bit = (w0 & 0x80000000u) != 0;
        const uint32_t xfer_sz = w0 & 0x7FFFu;
        const uint64_t ea = (static_cast<uint64_t>(eah_) << 32) | w1;

        if (xfer_sz > 0) {
            std::vector<uint8_t> buf(xfer_sz);
            if (is_get) {
                if (mem_->ReadMainMemory(ea, xfer_sz, buf.data())) {
                    mem_->WriteLs(cur_lsa, xfer_sz, buf.data());
                } else {
                    all_ok = false;
                }
            } else {
                mem_->ReadLs(cur_lsa, xfer_sz, buf.data());
                if (!mem_->WriteMainMemory(ea, xfer_sz, buf.data())) {
                    all_ok = false;
                }
            }
            cur_lsa = (cur_lsa + std::max<uint32_t>(xfer_sz, 16u)) & mem_->Lslr();
        }
        if (stall_bit) {
            list_stall_stat_ |= (1u << (tag_id_ & 31u));
            router.Events().RaiseEvent(EVT_MFC_LIST_STALL);
        }
    }
    history_.push_back(MfcDmaRecord{lsa_, (static_cast<uint64_t>(eah_) << 32) | eal_,
                                    list_bytes, static_cast<uint8_t>(tag_id_ & 31u),
                                    static_cast<uint16_t>(cmd & 0xFFFFu), all_ok});
    if (history_.size() > 128) history_.pop_front();
    return all_ok;
}

bool MfcDevice::ExecuteDma(uint32_t cmd, ChannelRouter &router) {
    last_cmd_ = cmd;
    if (!mem_) return false;
    const uint64_t ea = (static_cast<uint64_t>(eah_) << 32) | eal_;
    const uint8_t base = static_cast<uint8_t>(cmd & 0xFFu);

    // Strip fence/barrier modifier bits (0x01=barrier, 0x02=fence) for command matching
    const uint8_t kind = base & ~0x03u;
    bool ok = true;

    if (kind == 0x20 || kind == 0x28) {
        // PUT / PUTS (LS -> EA)
        const uint32_t sz = size_ & 0x7FFFu;
        std::vector<uint8_t> buf(sz);
        mem_->ReadLs(lsa_, sz, buf.data());
        ok = mem_->WriteMainMemory(ea, sz, buf.data());
    } else if (kind == 0x24) {
        // PUTL (DMA list LS -> EA)
        return ExecuteDmaList(cmd, false, router);
    } else if (kind == 0x40 || kind == 0x48) {
        // GET / GETS (EA -> LS)
        const uint32_t sz = size_ & 0x7FFFu;
        std::vector<uint8_t> buf(sz);
        ok = mem_->ReadMainMemory(ea, sz, buf.data());
        if (ok) mem_->WriteLs(lsa_, sz, buf.data());
    } else if (kind == 0x44) {
        // GETL (DMA list EA -> LS)
        return ExecuteDmaList(cmd, true, router);
    } else if (base == 0xA0 || base == 0xA1 || base == 0xA2) {
        // SNDSIG: send 4-byte word from LS to EA
        uint8_t buf[4] = {};
        mem_->ReadLs(lsa_, 4, buf);
        ok = mem_->WriteMainMemory(ea, 4, buf);
    } else if (base == 0xD0) {
        // GETLLAR: 128-byte atomic load + set reservation
        uint8_t line[128] = {};
        ok = mem_->ReadMainMemory(ea & ~uint64_t(0x7F), 128, line);
        if (ok) {
            mem_->WriteLs(lsa_ & ~0x7Fu, 128, line);
            mem_->SetReservation(ea);
            atomic_stat_ = 0x00000004u;  // GETLLAR completed
            atomic_stat_valid_ = 1;
        }
    } else if (base == 0xB4) {
        // PUTLLC: 128-byte conditional store
        const uint64_t line_ea = ea & ~uint64_t(0x7F);
        if (mem_->HasReservation() && mem_->ReservationEa() == line_ea) {
            uint8_t line[128] = {};
            mem_->ReadLs(lsa_ & ~0x7Fu, 128, line);
            ok = mem_->WriteMainMemory(line_ea, 128, line);
            mem_->ClearReservation();
            atomic_stat_ = 0u;  // 0 = conditional store succeeded!
        } else {
            atomic_stat_ = 1u;  // 1 = reservation lost / failed
        }
        atomic_stat_valid_ = 1;
    } else if (base == 0xB0 || base == 0xB8) {
        // PUTLLUC / PUTQLLUC: unconditional 128-byte store
        uint8_t line[128] = {};
        mem_->ReadLs(lsa_ & ~0x7Fu, 128, line);
        ok = mem_->WriteMainMemory(ea & ~uint64_t(0x7F), 128, line);
        mem_->ClearReservation();
        atomic_stat_ = (base == 0xB0) ? 0x00000002u : 0u;
        atomic_stat_valid_ = (base == 0xB0) ? 1u : 0u;
    } else {
        // BARRIER (0xC0), EIEIO (0xC8), SYNC (0xCC), or unrecognized command -> synchronous no-op
        ok = true;
    }

    history_.push_back(MfcDmaRecord{lsa_, ea, size_, static_cast<uint8_t>(tag_id_ & 31u),
                                    static_cast<uint16_t>(cmd & 0xFFFFu), ok});
    if (history_.size() > 128) history_.pop_front();
    return ok;
}

ChannelReadResult MfcDevice::Read(uint8_t ch, ChannelRouter &router) {
    (void)router;
    switch (ch) {
    case CH_MFC_RdTagMask:
        return { ChannelStatus::Ok, tag_mask_, "" };
    case CH_MFC_RdTagStat:
        tag_update_pending_ = 0;
        return { ChannelStatus::Ok, tag_stat_, "" };
    case CH_MFC_RdListStallStat:
        return { ChannelStatus::Ok, list_stall_stat_, "" };
    case CH_MFC_RdAtomicStat:
        atomic_stat_valid_ = 0;
        return { ChannelStatus::Ok, atomic_stat_, "" };
    default:
        return { ChannelStatus::Ok, 0, "" };
    }
}

ChannelWriteResult MfcDevice::Write(uint8_t ch, uint32_t val, ChannelRouter &router) {
    switch (ch) {
    case CH_MFC_WrMSSyncReq:
        router.Events().RaiseEvent(EVT_MULTISOURCE_SYNC);
        break;
    case CH_MFC_LSA:   lsa_ = val & 0x3FFFFu; break;
    case CH_MFC_EAH:   eah_ = val; break;
    case CH_MFC_EAL:   eal_ = val; break;
    case CH_MFC_Size:  size_ = val & 0xFFFFu; break;
    case CH_MFC_TagID: tag_id_ = val & 0x1Fu; break;
    case CH_MFC_Cmd:
        ExecuteDma(val, router);
        break;
    case CH_MFC_WrTagMask:
        tag_mask_ = val;
        break;
    case CH_MFC_WrTagUpdate:
        // Synchronous emulation: all queued DMAs are already complete!
        tag_stat_ = tag_mask_;
        tag_update_pending_ = 1;
        router.Events().RaiseEvent(EVT_MFC_TAG_STATUS_UPDATE);
        break;
    case CH_MFC_WrListStallAck:
        list_stall_stat_ &= ~val;
        break;
    default:
        break;
    }
    return { ChannelStatus::Ok, "" };
}

uint32_t MfcDevice::ReadCount(uint8_t ch, ChannelRouter &router) {
    (void)router;
    switch (ch) {
    case CH_MFC_Cmd:            return 16u;  // Full 16-entry MFC command queue available
    case CH_MFC_WrTagUpdate:    return 1u;   // Immediate update ready
    case CH_MFC_RdTagStat:      return tag_update_pending_ ? 1u : 1u;
    case CH_MFC_RdListStallStat:return list_stall_stat_ != 0 ? 1u : 0u;
    case CH_MFC_RdAtomicStat:   return atomic_stat_valid_;
    default:                    return 1u;
    }
}

std::string MfcDevice::Describe(uint8_t ch) const {
    (void)ch;
    char buf[192];
    std::snprintf(buf, sizeof(buf),
                  "mfc LSA=0x%05X EA=0x%08X%08X sz=0x%X tag=%u mask=0x%08X last_cmd=0x%X xfers=%zu",
                  lsa_, eah_, eal_, size_, tag_id_, tag_mask_, last_cmd_, history_.size());
    return buf;
}

// ---------------------------------------------------------------------------
// Built-in: MailboxDevice (ch28..ch30)
// ---------------------------------------------------------------------------
void MailboxDevice::Reset() {
    in_mbox_.clear();
    out_mbox_.clear();
    out_intr_mbox_.clear();
}

ChannelReadResult MailboxDevice::Read(uint8_t ch, ChannelRouter &router) {
    if (ch == CH_SPU_RdInMbox) {
        if (!in_mbox_.empty()) {
            const uint32_t v = in_mbox_.front();
            in_mbox_.pop_front();
            return { ChannelStatus::Ok, v, "" };
        }
        const EmptyPolicy policy = router.GetBreakFlags(ch).prompt_on_empty
                                       ? EmptyPolicy::Prompt
                                       : in_empty_policy_;
        if (policy == EmptyPolicy::Zero) return { ChannelStatus::Ok, 0, "in_mbox empty->0" };
        if (policy == EmptyPolicy::Stall) return { ChannelStatus::Stalled, 0, "SPU_RdInMbox empty" };
        if (policy == EmptyPolicy::Prompt) {
            uint32_t v = 0;
            if (router.TryInteractivePrompt(ch, &v)) return { ChannelStatus::Ok, v, "prompt" };
        }
        return { ChannelStatus::Break, 0, "SPU_RdInMbox empty (break)" };
    }
    return { ChannelStatus::Ok, 0, "" };
}

ChannelWriteResult MailboxDevice::Write(uint8_t ch, uint32_t val, ChannelRouter &router) {
    if (ch == CH_SPU_WrOutMbox) {
        out_mbox_.push_back(val);
        if (out_mbox_.size() > 64) out_mbox_.pop_front();
        router.Events().RaiseEvent(EVT_SPU_OUT_MBOX);
    } else if (ch == CH_SPU_WrOutIntrMbox) {
        out_intr_mbox_.push_back(val);
        if (out_intr_mbox_.size() > 64) out_intr_mbox_.pop_front();
        router.Events().RaiseEvent(EVT_SPU_OUT_INTR_MBOX);
    }
    return { ChannelStatus::Ok, "" };
}

uint32_t MailboxDevice::ReadCount(uint8_t ch, ChannelRouter &router) {
    (void)router;
    switch (ch) {
    case CH_SPU_WrOutMbox:     return 1u;  // Ready for SPU write
    case CH_SPU_WrOutIntrMbox: return 1u;  // Ready for SPU write
    case CH_SPU_RdInMbox:      return static_cast<uint32_t>(std::min<size_t>(in_mbox_.size(), 4u));
    default:                   return 0u;
    }
}

bool MailboxDevice::PushInput(uint8_t ch, uint32_t val) {
    if (ch == CH_SPU_RdInMbox) {
        in_mbox_.push_back(val);
        return true;
    }
    return false;
}

bool MailboxDevice::PopOutput(uint8_t ch, uint32_t *out) {
    if (ch == CH_SPU_WrOutMbox && !out_mbox_.empty()) {
        if (out) *out = out_mbox_.front();
        out_mbox_.pop_front();
        return true;
    }
    if (ch == CH_SPU_WrOutIntrMbox && !out_intr_mbox_.empty()) {
        if (out) *out = out_intr_mbox_.front();
        out_intr_mbox_.pop_front();
        return true;
    }
    return false;
}

std::string MailboxDevice::Describe(uint8_t ch) const {
    (void)ch;
    char buf[128];
    std::snprintf(buf, sizeof(buf), "mailbox in=%zu out=%zu out_intr=%zu",
                  in_mbox_.size(), out_mbox_.size(), out_intr_mbox_.size());
    return buf;
}

// ---------------------------------------------------------------------------
// ChannelRouter
// ---------------------------------------------------------------------------
ChannelRouter::ChannelRouter(SpuMemory *mem)
    : mem_(mem),
      events_(std::make_shared<EventDecDevice>()),
      mfc_(std::make_shared<MfcDevice>(mem)),
      mailbox_(std::make_shared<MailboxDevice>()),
      default_stub_(std::make_shared<StubLoggerDevice>("unassigned", 0, 1)) {
    ResetToDefaults();
}

void ChannelRouter::ResetToDefaults() {
    slots_.fill(nullptr);
    flags_.fill(ChannelBreakFlags{});
    log_.clear();

    events_->Reset();
    mfc_->Reset();
    mailbox_->Reset();

    // Event & Decrementer channels
    for (uint8_t ch : { uint8_t(0), uint8_t(1), uint8_t(2), uint8_t(3), uint8_t(4),
                        uint8_t(7), uint8_t(8), uint8_t(11), uint8_t(13), uint8_t(14), uint8_t(15) }) {
        slots_[ch] = events_;
    }

    // MFC channels
    slots_[CH_MFC_WrMSSyncReq] = mfc_;
    slots_[CH_MFC_RdTagMask] = mfc_;
    for (uint8_t ch = 16; ch <= 27; ++ch) {
        slots_[ch] = mfc_;
    }

    // Mailbox channels
    slots_[CH_SPU_WrOutMbox] = mailbox_;
    slots_[CH_SPU_RdInMbox] = mailbox_;
    slots_[CH_SPU_WrOutIntrMbox] = mailbox_;

    // PS3 Isolation channels (64..68) default to per-channel FIFOs (break on empty read)
    for (uint8_t ch = 64; ch <= 68; ++ch) {
        slots_[ch] = std::make_shared<FifoChannelDevice>(
            std::string("ps3_iso_") + std::to_string(ch), EmptyPolicy::Break, 0u);
    }
}

void ChannelRouter::ResetState() {
    std::vector<ISpuChannelDevice *> seen;
    for (const auto &sp : slots_) {
        if (!sp) continue;
        if (std::find(seen.begin(), seen.end(), sp.get()) == seen.end()) {
            sp->Reset();
            seen.push_back(sp.get());
        }
    }
    log_.clear();
}

void ChannelRouter::AttachDevice(uint8_t ch, std::shared_ptr<ISpuChannelDevice> dev) {
    slots_[ch & 0x7Fu] = std::move(dev);
}

void ChannelRouter::DetachDevice(uint8_t ch) {
    slots_[ch & 0x7Fu].reset();
}

std::shared_ptr<ISpuChannelDevice> ChannelRouter::GetDevice(uint8_t ch) const {
    const auto &sp = slots_[ch & 0x7Fu];
    return sp ? sp : default_stub_;
}

bool ChannelRouter::TryInteractivePrompt(uint8_t ch, uint32_t *val_out) const {
    if (!prompt_cb_) return false;
    return prompt_cb_(ch, cur_pc_, val_out);
}

void ChannelRouter::RecordLog(uint64_t cycle, uint32_t pc, uint8_t ch, char op, uint32_t val,
                              ChannelStatus status, const std::string &note) {
    if (log_.size() >= 256) log_.pop_front();
    log_.push_back(ChannelLogEntry{cycle, pc, ch, op, val, status, note});
}

ChannelReadResult ChannelRouter::ReadChannel(uint8_t ch, uint32_t pc, uint64_t cycle) {
    const uint8_t id = ch & 0x7Fu;
    cur_pc_ = pc;
    auto dev = GetDevice(id);
    ChannelReadResult res = dev->Read(id, *this);
    if (res.status == ChannelStatus::Ok && flags_[id].break_on_read) {
        res.status = ChannelStatus::Break;
        res.reason = "break_on_read";
    }
    RecordLog(cycle, pc, id, 'R', res.value, res.status, res.reason);
    return res;
}

ChannelWriteResult ChannelRouter::WriteChannel(uint8_t ch, uint32_t val, uint32_t pc, uint64_t cycle) {
    const uint8_t id = ch & 0x7Fu;
    cur_pc_ = pc;
    auto dev = GetDevice(id);
    ChannelWriteResult res = dev->Write(id, val, *this);
    if (res.status == ChannelStatus::Ok && flags_[id].break_on_write) {
        res.status = ChannelStatus::Break;
        res.reason = "break_on_write";
    }
    RecordLog(cycle, pc, id, 'W', val, res.status, res.reason);
    return res;
}

uint32_t ChannelRouter::ReadChannelCount(uint8_t ch, uint32_t pc, uint64_t cycle) {
    const uint8_t id = ch & 0x7Fu;
    cur_pc_ = pc;
    auto dev = GetDevice(id);
    const uint32_t cnt = dev->ReadCount(id, *this);
    RecordLog(cycle, pc, id, 'C', cnt, ChannelStatus::Ok, "");
    return cnt;
}

void ChannelRouter::Tick(uint64_t delta_cycles) {
    events_->OnTick(delta_cycles, *this);
}

bool ChannelRouter::PushInput(uint8_t ch, uint32_t val) {
    const uint8_t id = ch & 0x7Fu;
    auto dev = GetDevice(id);
    const bool ok = dev->PushInput(id, val);
    if (ok && id == CH_SPU_RdInMbox) {
        events_->RaiseEvent(EVT_SPU_IN_MBOX_AVAIL);
    }
    return ok;
}

bool ChannelRouter::PopOutput(uint8_t ch, uint32_t *out) {
    const uint8_t id = ch & 0x7Fu;
    return GetDevice(id)->PopOutput(id, out);
}

bool ChannelRouter::SetValue(uint8_t ch, uint32_t val) {
    const uint8_t id = ch & 0x7Fu;
    return GetDevice(id)->SetValue(id, val);
}

bool ChannelRouter::SetCount(uint8_t ch, uint32_t cnt) {
    const uint8_t id = ch & 0x7Fu;
    return GetDevice(id)->SetCount(id, cnt);
}

// ---------------------------------------------------------------------------
// JSON Config Loader & Saver
// ---------------------------------------------------------------------------
bool ChannelRouter::LoadConfigFile(const std::string &path, std::string *err_out) {
    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        if (err_out) *err_out = "Cannot open channel config file: " + path;
        return false;
    }
    std::ostringstream ss;
    ss << ifs.rdbuf();
    const size_t slash = path.find_last_of("\\/");
    const std::string base_dir = (slash == std::string::npos) ? "" : path.substr(0, slash);
    return LoadConfigJson(ss.str(), base_dir, err_out);
}

bool ChannelRouter::LoadConfigJson(const std::string &json_text, const std::string &base_dir,
                                   std::string *err_out) {
    JsonValue root;
    JsonParser parser(json_text);
    if (!parser.Parse(&root, err_out)) return false;
    if (!root.IsObject()) {
        if (err_out) *err_out = "Top-level JSON must be an object";
        return false;
    }

    // Optional: "reset": true to reset to defaults before applying
    if (const JsonValue *rv = root.Get("reset")) {
        if (rv->AsBool(false)) ResetToDefaults();
    }

    // 1. DMA / Main Memory EA regions
    if (const JsonValue *regs = root.Get("dma_regions")) {
        if (regs->IsArray() && mem_) {
            for (const auto &item : regs->arr) {
                if (!item.IsObject()) continue;
                const uint64_t ea = item.Get("ea") ? item.Get("ea")->AsU64(0) : 0;
                const std::string name = item.Get("name") ? item.Get("name")->AsString("dma_region") : "dma_region";
                const bool ro = item.Get("read_only") ? item.Get("read_only")->AsBool(false) : false;

                if (const JsonValue *fv = item.Get("file")) {
                    std::string fpath = fv->AsString();
                    if (!FileExists(fpath) && !base_dir.empty()) {
                        fpath = JoinPath(base_dir, fpath);
                    }
                    std::ifstream bf(fpath, std::ios::binary);
                    if (!bf.is_open()) {
                        if (err_out) *err_out = "Cannot open DMA region file: " + fpath;
                        return false;
                    }
                    std::vector<uint8_t> data((std::istreambuf_iterator<char>(bf)),
                                              std::istreambuf_iterator<char>());
                    const size_t req_sz = item.Get("size") ? static_cast<size_t>(item.Get("size")->AsU64(data.size())) : data.size();
                    if (req_sz > data.size()) data.resize(req_sz, 0);
                    mem_->MapMainMemoryData(ea, data.data(), data.size(), name, ro);
                } else if (const JsonValue *hv = item.Get("hex")) {
                    std::vector<uint8_t> data;
                    if (!DecodeHexBytes(hv->AsString(), &data)) {
                        if (err_out) *err_out = "Invalid hex string in dma_regions";
                        return false;
                    }
                    const size_t req_sz = item.Get("size") ? static_cast<size_t>(item.Get("size")->AsU64(data.size())) : data.size();
                    if (req_sz > data.size()) data.resize(req_sz, 0);
                    mem_->MapMainMemoryData(ea, data.data(), data.size(), name, ro);
                } else {
                    const size_t sz = item.Get("size") ? static_cast<size_t>(item.Get("size")->AsU64(0x1000)) : 0x1000;
                    mem_->MapMainMemory(ea, sz, name, ro);
                }
            }
        }
    }

    // 2. Channel devices
    if (const JsonValue *devs = root.Get("devices")) {
        if (!devs->IsArray()) {
            if (err_out) *err_out = "'devices' must be an array";
            return false;
        }
        for (const auto &d : devs->arr) {
            if (!d.IsObject()) continue;

            // Collect target channel(s): either "channel" (int/string) or "channels" (array)
            std::vector<uint8_t> ch_list;
            if (const JsonValue *cv = d.Get("channel")) {
                uint8_t id = 0;
                if (cv->IsString()) {
                    if (ParseChannelId(cv->sval, &id)) ch_list.push_back(id);
                } else if (cv->IsNumber() && cv->uval < 128u) {
                    ch_list.push_back(static_cast<uint8_t>(cv->uval));
                }
            }
            if (const JsonValue *cvs = d.Get("channels")) {
                if (cvs->IsArray()) {
                    for (const auto &elem : cvs->arr) {
                        uint8_t id = 0;
                        if (elem.IsString() && ParseChannelId(elem.sval, &id)) ch_list.push_back(id);
                        else if (elem.IsNumber() && elem.uval < 128u) ch_list.push_back(static_cast<uint8_t>(elem.uval));
                    }
                }
            }
            if (ch_list.empty()) {
                if (err_out) *err_out = "Device entry missing valid 'channel' or 'channels'";
                return false;
            }

            const std::string type = d.Get("type") ? d.Get("type")->AsString("fifo") : "fifo";
            const std::string name = d.Get("name") ? d.Get("name")->AsString(type) : type;
            std::shared_ptr<ISpuChannelDevice> dev;

            if (StrIEq(type, "fifo")) {
                const EmptyPolicy ep = d.Get("on_empty") ? ParseEmptyPolicy(d.Get("on_empty")->AsString()) : EmptyPolicy::Break;
                const uint32_t def_val = d.Get("default") ? d.Get("default")->AsU32(0) : 0;
                auto fifo = std::make_shared<FifoChannelDevice>(name, ep, def_val);
                if (const JsonValue *rx = d.Get("rx")) {
                    if (rx->IsArray()) {
                        std::vector<uint32_t> vals;
                        vals.reserve(rx->arr.size());
                        for (const auto &v : rx->arr) vals.push_back(v.AsU32(0));
                        fifo->SetInitialRx(vals);
                    }
                }
                if (const JsonValue *cv = d.Get("count")) {
                    fifo->SetCount(ch_list[0], cv->AsU32(0));
                }
                dev = fifo;
            } else if (StrIEq(type, "register")) {
                const uint32_t val = d.Get("value") ? d.Get("value")->AsU32(0) : 0;
                const uint32_t cnt = d.Get("count") ? d.Get("count")->AsU32(1) : 1;
                const bool ro = d.Get("read_only") ? d.Get("read_only")->AsBool(false) : false;
                const bool clr = d.Get("clear_on_read") ? d.Get("clear_on_read")->AsBool(false) : false;
                dev = std::make_shared<RegisterChannelDevice>(name, val, cnt, ro, clr);
            } else if (StrIEq(type, "responder")) {
                const EmptyPolicy ep = d.Get("on_empty") ? ParseEmptyPolicy(d.Get("on_empty")->AsString()) : EmptyPolicy::Break;
                auto resp = std::make_shared<ResponderChannelDevice>(name, ep);
                if (const JsonValue *rules = d.Get("rules")) {
                    if (rules->IsArray()) {
                        for (const auto &rj : rules->arr) {
                            if (!rj.IsObject()) continue;
                            ResponderRule rr;
                            if (const JsonValue *ww = rj.Get("when_write")) {
                                if (ww->IsString() && (ww->sval == "*" || StrIEq(ww->sval, "any") || StrIEq(ww->sval, "default"))) {
                                    rr.match_any = true;
                                } else {
                                    rr.when_write = ww->AsU32(0);
                                }
                            } else {
                                rr.match_any = true;
                            }
                            if (const JsonValue *rc = rj.Get("reply_channel")) {
                                uint8_t tid = 0;
                                if (rc->IsString() && ParseChannelId(rc->sval, &tid)) rr.reply_channel = tid;
                                else if (rc->IsNumber() && rc->uval < 128u) rr.reply_channel = static_cast<int>(rc->uval);
                            }
                            if (const JsonValue *rep = rj.Get("reply")) {
                                if (rep->IsArray()) {
                                    for (const auto &v : rep->arr) rr.reply_words.push_back(v.AsU32(0));
                                } else {
                                    rr.reply_words.push_back(rep->AsU32(0));
                                }
                            }
                            if (const JsonValue *ev = rj.Get("raise_event")) {
                                rr.raise_event = ev->AsU32(0);
                            }
                            resp->AddRule(rr);
                        }
                    }
                }
                if (const JsonValue *rx = d.Get("rx")) {
                    if (rx->IsArray()) {
                        for (const auto &v : rx->arr) resp->PushInput(ch_list[0], v.AsU32(0));
                    }
                }
                dev = resp;
            } else if (StrIEq(type, "stub") || StrIEq(type, "logger")) {
                const uint32_t dr = d.Get("default_read") ? d.Get("default_read")->AsU32(0) : 0;
                const uint32_t dc = d.Get("default_count") ? d.Get("default_count")->AsU32(1) : 1;
                dev = std::make_shared<StubLoggerDevice>(name, dr, dc);
            } else if (StrIEq(type, "mailbox")) {
                if (const JsonValue *ep = d.Get("on_empty")) {
                    mailbox_->SetInMboxEmptyPolicy(ParseEmptyPolicy(ep->AsString()));
                }
                if (const JsonValue *rx = d.Get("rx")) {
                    if (rx->IsArray()) {
                        for (const auto &v : rx->arr) PushInput(CH_SPU_RdInMbox, v.AsU32(0));
                    }
                }
                dev = mailbox_;
            } else if (StrIEq(type, "mfc")) {
                dev = mfc_;
            } else if (StrIEq(type, "event")) {
                dev = events_;
            } else {
                if (err_out) *err_out = "Unknown channel device type: " + type;
                return false;
            }

            const bool br_rd = d.Get("break_on_read") ? d.Get("break_on_read")->AsBool(false) : false;
            const bool br_wr = d.Get("break_on_write") ? d.Get("break_on_write")->AsBool(false) : false;
            const bool pr_em = d.Get("prompt_on_empty") ? d.Get("prompt_on_empty")->AsBool(false) : false;

            for (uint8_t ch : ch_list) {
                AttachDevice(ch, dev);
                flags_[ch].break_on_read = br_rd;
                flags_[ch].break_on_write = br_wr;
                flags_[ch].prompt_on_empty = pr_em;
            }
        }
    }

    return true;
}

std::string ChannelRouter::ExportConfigJson() const {
    std::ostringstream oss;
    oss << "{\n  \"dma_regions\": [\n";
    if (mem_) {
        const auto &regs = mem_->MainRegions();
        for (size_t i = 0; i < regs.size(); ++i) {
            char eabuf[32];
            std::snprintf(eabuf, sizeof(eabuf), "0x%llX", static_cast<unsigned long long>(regs[i].base));
            oss << "    { \"name\": \"" << EscapeJson(regs[i].name)
                << "\", \"ea\": \"" << eabuf
                << "\", \"size\": " << regs[i].data.size()
                << ", \"read_only\": " << (regs[i].read_only ? "true" : "false") << " }";
            if (i + 1 < regs.size()) oss << ",";
            oss << "\n";
        }
    }
    oss << "  ],\n  \"devices\": [\n";

    bool first = true;
    for (uint8_t ch = 0; ch < 128; ++ch) {
        const auto &sp = slots_[ch];
        if (!sp) continue;
        // Skip built-in unmodified architectural channels unless flags set
        const std::string tn = sp->TypeName();
        const bool is_builtin = (tn == "event" || tn == "mfc" || tn == "mailbox");
        const bool has_flags = flags_[ch].break_on_read || flags_[ch].break_on_write || flags_[ch].prompt_on_empty;
        if (is_builtin && !has_flags) continue;

        if (!first) oss << ",\n";
        first = false;
        oss << "    { \"channel\": ";
        if (const char *sym = ChannelSymbolicName(ch)) {
            oss << "\"" << sym << "\"";
        } else {
            oss << static_cast<unsigned>(ch);
        }
        oss << ", \"type\": \"" << EscapeJson(tn)
            << "\", \"name\": \"" << EscapeJson(sp->Name()) << "\"";

        if (auto *fifo = dynamic_cast<const FifoChannelDevice *>(sp.get())) {
            oss << ", \"on_empty\": \"" << EmptyPolicyName(fifo->GetEmptyPolicy()) << "\", \"rx\": [";
            const auto &q = fifo->RxQueue();
            for (size_t k = 0; k < q.size(); ++k) {
                char hb[16];
                std::snprintf(hb, sizeof(hb), "\"0x%08X\"", q[k]);
                if (k) oss << ", ";
                oss << hb;
            }
            oss << "]";
        } else if (auto *reg = dynamic_cast<const RegisterChannelDevice *>(sp.get())) {
            char hb[16];
            std::snprintf(hb, sizeof(hb), "\"0x%08X\"", reg->Value());
            oss << ", \"value\": " << hb;
        } else if (auto *resp = dynamic_cast<const ResponderChannelDevice *>(sp.get())) {
            oss << ", \"rules\": [";
            const auto &rs = resp->Rules();
            for (size_t k = 0; k < rs.size(); ++k) {
                if (k) oss << ", ";
                oss << "{ \"when_write\": ";
                if (rs[k].match_any) {
                    oss << "\"*\"";
                } else {
                    char hb[16];
                    std::snprintf(hb, sizeof(hb), "\"0x%08X\"", rs[k].when_write);
                    oss << hb;
                }
                oss << ", \"reply\": [";
                for (size_t j = 0; j < rs[k].reply_words.size(); ++j) {
                    char hb[16];
                    std::snprintf(hb, sizeof(hb), "\"0x%08X\"", rs[k].reply_words[j]);
                    if (j) oss << ", ";
                    oss << hb;
                }
                oss << "]";
                if (rs[k].reply_channel >= 0) oss << ", \"reply_channel\": " << rs[k].reply_channel;
                if (rs[k].raise_event != 0) oss << ", \"raise_event\": " << rs[k].raise_event;
                oss << " }";
            }
            oss << "]";
        }

        if (flags_[ch].break_on_read) oss << ", \"break_on_read\": true";
        if (flags_[ch].break_on_write) oss << ", \"break_on_write\": true";
        if (flags_[ch].prompt_on_empty) oss << ", \"prompt_on_empty\": true";
        oss << " }";
    }
    oss << "\n  ]\n}\n";
    return oss.str();
}

bool ChannelRouter::SaveConfigFile(const std::string &path, std::string *err_out) const {
    std::ofstream ofs(path);
    if (!ofs.is_open()) {
        if (err_out) *err_out = "Cannot write channel config file: " + path;
        return false;
    }
    ofs << ExportConfigJson();
    return ofs.good();
}

std::string ChannelRouter::FormatSummary() const {
    std::ostringstream oss;
    oss << "Attached SPU Channel Devices:\n";
    for (uint8_t ch = 0; ch < 128; ++ch) {
        if (!slots_[ch]) continue;
        const char *sym = ChannelSymbolicName(ch);
        char hdr[64];
        if (sym) std::snprintf(hdr, sizeof(hdr), "  ch%-3u (%-19s): ", ch, sym);
        else     std::snprintf(hdr, sizeof(hdr), "  ch%-3u (%-19s): ", ch, "");
        oss << hdr << slots_[ch]->Describe(ch);
        if (flags_[ch].break_on_read) oss << " [BRK_RD]";
        if (flags_[ch].break_on_write) oss << " [BRK_WR]";
        if (flags_[ch].prompt_on_empty) oss << " [PROMPT]";
        oss << "\n";
    }
    return oss.str();
}

}  // namespace spu
