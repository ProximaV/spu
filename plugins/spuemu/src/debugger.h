#pragma once

#include <atomic>
#include <cstdint>
#include <string>

namespace spu {

class SpuMachine;
struct StopInfo;

class GdbServer {
public:
    explicit GdbServer(SpuMachine *machine, int port = 23946);
    ~GdbServer();

    GdbServer(const GdbServer &) = delete;
    GdbServer &operator=(const GdbServer &) = delete;

    bool WaitForConnection();
    void Stop();
    int Port() const { return port_; }

    // Exposed for socket-free unit testing
    std::string ProcessPacket(const std::string &payload, bool *should_disconnect_out = nullptr);

private:
    static std::string ToHexBytes(const uint8_t *data, size_t len);
    static std::string HexDecodeString(const std::string &hex);
    static std::string HexEncodeString(const std::string &text);
    static uint8_t Checksum(const std::string &payload);

    std::string BuildStopReply(const StopInfo &info) const;
    std::string BuildTargetXml() const;
    std::string HandleXfer(const std::string &full_data, size_t offset, size_t length) const;
    std::string HandleMonitor(const std::string &cmd);

    bool SendRaw(intptr_t sock, const std::string &data);
    bool SendPacket(intptr_t sock, const std::string &payload);
    bool ReadPacket(intptr_t sock, std::string *payload_out, bool *ctrl_c_out);

    SpuMachine *machine_ = nullptr;
    int port_ = 23946;
    bool no_ack_mode_ = false;
    bool resume_ignore_bpt_ = false;
    intptr_t active_client_ = -1;
    std::atomic<bool> stop_requested_{false};
};

}  // namespace spu
