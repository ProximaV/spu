#include "debugger.h"

#include "log.h"
#include "machine.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using socklen_t = int;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace spu {

namespace {

void CloseSock(intptr_t s) {
    if (s < 0) return;
#ifdef _WIN32
    closesocket(static_cast<SOCKET>(s));
#else
    close(static_cast<int>(s));
#endif
}

int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}  // namespace

GdbServer::GdbServer(SpuMachine *machine, int port)
    : machine_(machine), port_(port) {
#ifdef _WIN32
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
}

GdbServer::~GdbServer() {
    Stop();
}

void GdbServer::Stop() {
    stop_requested_.store(true);
    if (active_client_ >= 0) {
        CloseSock(active_client_);
        active_client_ = -1;
    }
}

std::string GdbServer::ToHexBytes(const uint8_t *data, size_t len) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0xF]);
    }
    return out;
}

std::string GdbServer::HexEncodeString(const std::string &text) {
    return ToHexBytes(reinterpret_cast<const uint8_t *>(text.data()), text.size());
}

std::string GdbServer::HexDecodeString(const std::string &hex) {
    std::string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = HexVal(hex[i]);
        const int lo = HexVal(hex[i + 1]);
        if (hi < 0 || lo < 0) break;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return out;
}

uint8_t GdbServer::Checksum(const std::string &payload) {
    uint8_t sum = 0;
    for (char c : payload) sum = static_cast<uint8_t>(sum + static_cast<uint8_t>(c));
    return sum;
}

std::string GdbServer::BuildStopReply(const StopInfo &info) const {
    int sig = 5;  // SIGTRAP
    if (info.reason == StopReason::InvalidInsn) sig = 4;  // SIGILL
    char buf[32];
    std::snprintf(buf, sizeof(buf), "S%02X", sig);
    return buf;
}

std::string GdbServer::BuildTargetXml() const {
    std::ostringstream oss;
    oss << "<?xml version=\"1.0\"?>\n<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n"
        << "<target version=\"1.0\">\n<architecture>spu</architecture>\n"
        << "<feature name=\"org.gnu.gdb.spu.core\">\n";
    for (int i = 0; i < 128; ++i) {
        oss << "  <reg name=\"r" << i << "\" bitsize=\"128\" type=\"uint128\" regnum=\"" << i << "\"/>\n";
    }
    oss << "  <reg name=\"id\" bitsize=\"32\" type=\"uint32\" regnum=\"128\"/>\n"
        << "  <reg name=\"pc\" bitsize=\"32\" type=\"code_ptr\" regnum=\"129\"/>\n"
        << "</feature>\n</target>\n";
    return oss.str();
}

std::string GdbServer::HandleXfer(const std::string &full_data, size_t offset, size_t length) const {
    if (offset >= full_data.size()) return "l";
    const size_t avail = full_data.size() - offset;
    const size_t n = std::min(avail, length);
    const char prefix = (offset + n >= full_data.size()) ? 'l' : 'm';
    return std::string(1, prefix) + full_data.substr(offset, n);
}

std::string GdbServer::HandleMonitor(const std::string &cmd) {
    std::string out;
    machine_->ExecuteCommand(cmd, out);
    if (out.empty() || out.back() != '\n') out.push_back('\n');
    return HexEncodeString(out);
}

std::string GdbServer::ProcessPacket(const std::string &payload, bool *should_disconnect_out) {
    if (should_disconnect_out) *should_disconnect_out = false;
    if (payload.empty()) return "";

    if (payload == "?") {
        return "S05";
    }
    if (payload == "QStartNoAckMode") {
        no_ack_mode_ = true;
        return "OK";
    }
    if (payload.rfind("qSupported", 0) == 0) {
        return "PacketSize=4096;QStartNoAckMode+;qXfer:features:read+";
    }
    if (payload.rfind("qXfer:features:read:target.xml:", 0) == 0) {
        const std::string rest = payload.substr(31);
        const size_t comma = rest.find(',');
        const size_t off = std::strtoul(rest.substr(0, comma).c_str(), nullptr, 16);
        const size_t len = (comma != std::string::npos) ? std::strtoul(rest.substr(comma + 1).c_str(), nullptr, 16) : 1024;
        return HandleXfer(BuildTargetXml(), off, len);
    }
    if (payload.rfind("qRcmd,", 0) == 0) {
        return HandleMonitor(HexDecodeString(payload.substr(6)));
    }
    if (payload == "g") {
        std::string out;
        out.reserve(128 * 32 + 16);
        for (uint8_t r = 0; r < 128; ++r) {
            out += ToHexBytes(machine_->cpu.Reg(r).b.data(), 16);
        }
        uint8_t id_be[4] = { 0, 0, 0, 0 };
        const uint32_t pc = machine_->cpu.GetPC();
        uint8_t pc_be[4] = {
            static_cast<uint8_t>(pc >> 24), static_cast<uint8_t>(pc >> 16),
            static_cast<uint8_t>(pc >> 8), static_cast<uint8_t>(pc)
        };
        out += ToHexBytes(id_be, 4);
        out += ToHexBytes(pc_be, 4);
        return out;
    }
    if (payload[0] == 'p') {
        const uint32_t regno = static_cast<uint32_t>(std::strtoul(payload.substr(1).c_str(), nullptr, 16));
        if (regno < 128u) {
            return ToHexBytes(machine_->cpu.Reg(static_cast<uint8_t>(regno)).b.data(), 16);
        }
        if (regno == 128u) return "00000000";
        if (regno == 129u) {
            const uint32_t pc = machine_->cpu.GetPC();
            uint8_t b[4] = { static_cast<uint8_t>(pc >> 24), static_cast<uint8_t>(pc >> 16),
                             static_cast<uint8_t>(pc >> 8), static_cast<uint8_t>(pc) };
            return ToHexBytes(b, 4);
        }
        return "E01";
    }
    if (payload[0] == 'P') {
        const size_t eq = payload.find('=');
        if (eq == std::string::npos) return "E01";
        const uint32_t regno = static_cast<uint32_t>(std::strtoul(payload.substr(1, eq - 1).c_str(), nullptr, 16));
        const std::string hex = payload.substr(eq + 1);
        const std::string bytes = HexDecodeString(hex);
        if (regno < 128u && bytes.size() == 16) {
            Quadword q;
            std::memcpy(q.b.data(), bytes.data(), 16);
            machine_->cpu.Reg(static_cast<uint8_t>(regno)) = q;
            return "OK";
        }
        if (regno == 129u && bytes.size() == 4) {
            const uint32_t pc = (static_cast<uint8_t>(bytes[0]) << 24) |
                                (static_cast<uint8_t>(bytes[1]) << 16) |
                                (static_cast<uint8_t>(bytes[2]) << 8) |
                                static_cast<uint8_t>(bytes[3]);
            machine_->cpu.SetPC(pc);
            return "OK";
        }
        return "E01";
    }
    if (payload[0] == 'm') {
        const size_t comma = payload.find(',');
        if (comma == std::string::npos) return "E01";
        const uint32_t addr = static_cast<uint32_t>(std::strtoul(payload.substr(1, comma - 1).c_str(), nullptr, 16));
        const size_t len = std::strtoul(payload.substr(comma + 1).c_str(), nullptr, 16);
        std::vector<uint8_t> buf(len);
        machine_->mem.ReadLs(addr, len, buf.data());
        return ToHexBytes(buf.data(), buf.size());
    }
    if (payload[0] == 'M') {
        const size_t comma = payload.find(',');
        const size_t colon = payload.find(':');
        if (comma == std::string::npos || colon == std::string::npos) return "E01";
        const uint32_t addr = static_cast<uint32_t>(std::strtoul(payload.substr(1, comma - 1).c_str(), nullptr, 16));
        const std::string bytes = HexDecodeString(payload.substr(colon + 1));
        machine_->mem.WriteLs(addr, bytes.size(), bytes.data());
        return "OK";
    }
    if (payload[0] == 'Z' || payload[0] == 'z') {
        const bool is_add = (payload[0] == 'Z');
        const size_t c1 = payload.find(',');
        const size_t c2 = payload.find(',', c1 == std::string::npos ? 0 : c1 + 1);
        if (c1 == std::string::npos || c2 == std::string::npos) return "E01";
        const int type = std::atoi(payload.substr(1, c1 - 1).c_str());
        const uint32_t addr = static_cast<uint32_t>(std::strtoul(payload.substr(c1 + 1, c2 - c1 - 1).c_str(), nullptr, 16));
        const uint32_t kind = static_cast<uint32_t>(std::strtoul(payload.substr(c2 + 1).c_str(), nullptr, 16));
        if (type == 0 || type == 1) {
            if (is_add) machine_->cpu.AddBreakpoint(addr);
            else machine_->cpu.RemoveBreakpoint(addr);
            return "OK";
        }
        if (type >= 2 && type <= 4) {
            const int wt = (type == 2) ? 1 : (type == 3) ? 2 : 3;
            if (is_add) machine_->mem.AddWatchpoint(addr, kind ? kind : 4u, wt);
            else machine_->mem.RemoveWatchpoint(addr, kind ? kind : 4u, wt);
            return "OK";
        }
        return "";
    }
    if (payload == "s") {
        const StopInfo st = machine_->Step(true);
        resume_ignore_bpt_ = (st.reason == StopReason::Breakpoint);
        return BuildStopReply(st);
    }
    if (payload == "c") {
        const StopInfo st = machine_->RunSteps(5000000ULL, resume_ignore_bpt_, &stop_requested_);
        resume_ignore_bpt_ = (st.reason == StopReason::Breakpoint);
        return BuildStopReply(st);
    }
    if (payload == "D" || payload == "k") {
        if (should_disconnect_out) *should_disconnect_out = true;
        return "OK";
    }
    return "";
}

bool GdbServer::SendRaw(intptr_t sock, const std::string &data) {
    size_t sent = 0;
    while (sent < data.size()) {
        const int n = send(static_cast<SOCKET>(sock), data.data() + sent,
                           static_cast<int>(data.size() - sent), 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool GdbServer::SendPacket(intptr_t sock, const std::string &payload) {
    char csum[8];
    std::snprintf(csum, sizeof(csum), "#%02x", Checksum(payload));
    return SendRaw(sock, "$" + payload + csum);
}

bool GdbServer::ReadPacket(intptr_t sock, std::string *payload_out, bool *ctrl_c_out) {
    if (ctrl_c_out) *ctrl_c_out = false;
    payload_out->clear();
    char ch = 0;
    while (!stop_requested_.load()) {
        const int n = recv(static_cast<SOCKET>(sock), &ch, 1, 0);
        if (n <= 0) return false;
        if (ch == 0x03) {
            if (ctrl_c_out) *ctrl_c_out = true;
            return true;
        }
        if (ch == '$') break;
    }
    while (!stop_requested_.load()) {
        const int n = recv(static_cast<SOCKET>(sock), &ch, 1, 0);
        if (n <= 0) return false;
        if (ch == '#') {
            char cbuf[2] = {};
            if (recv(static_cast<SOCKET>(sock), cbuf, 2, 0) <= 0) return false;
            if (!no_ack_mode_) SendRaw(sock, "+");
            return true;
        }
        payload_out->push_back(ch);
    }
    return false;
}

bool GdbServer::WaitForConnection() {
    const intptr_t lsock = static_cast<intptr_t>(socket(AF_INET, SOCK_STREAM, 0));
    if (lsock < 0) return false;
    int opt = 1;
    setsockopt(static_cast<SOCKET>(lsock), SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char *>(&opt), sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(static_cast<uint16_t>(port_));
    if (bind(static_cast<SOCKET>(lsock), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0 ||
        listen(static_cast<SOCKET>(lsock), 1) != 0) {
        CloseSock(lsock);
        return false;
    }
    SPU_LOG("GDB RSP listening on 127.0.0.1:%d", port_);
    sockaddr_in cli{};
    socklen_t clen = sizeof(cli);
    const intptr_t csock = static_cast<intptr_t>(
        accept(static_cast<SOCKET>(lsock), reinterpret_cast<sockaddr *>(&cli), &clen));
    CloseSock(lsock);
    if (csock < 0) return false;

    active_client_ = csock;
    no_ack_mode_ = false;
    while (!stop_requested_.load()) {
        std::string pkt;
        bool ctrl_c = false;
        if (!ReadPacket(csock, &pkt, &ctrl_c)) break;
        if (ctrl_c) {
            SendPacket(csock, "S02");
            continue;
        }
        bool disconnect = false;
        const std::string reply = ProcessPacket(pkt, &disconnect);
        if (!SendPacket(csock, reply)) break;
        if (disconnect) break;
    }
    CloseSock(csock);
    active_client_ = -1;
    return true;
}

}  // namespace spu
