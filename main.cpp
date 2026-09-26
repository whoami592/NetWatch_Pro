/* NetWatch Pro 1.0
 * Coded by Cyber Security Engineer Mr Sabaz Ali Khan
 * C++11; Windows Winsock and POSIX TCP service monitoring.
 */
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <direct.h>
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#endif
#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <cerrno>
#include <cstdio>
#include <cmath>

using Clock = std::chrono::steady_clock;
volatile std::sig_atomic_t stopped = 0;
void stopSignal(int) { stopped = 1; }
#ifdef _WIN32
using Socket = SOCKET;
const Socket badSocket = INVALID_SOCKET;
int socketError() { return WSAGetLastError(); }
void closeSocket(Socket s) { closesocket(s); }
bool pending(int e) { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
#else
using Socket = int;
const Socket badSocket = -1;
int socketError() { return errno; }
void closeSocket(Socket s) { close(s); }
bool pending(int e) { return e == EINPROGRESS || e == EWOULDBLOCK; }
#endif
struct Network {
    Network() {
#ifdef _WIN32
        WSADATA data;
        if (WSAStartup(MAKEWORD(2,2), &data)) throw std::runtime_error("Winsock startup failed.");
#endif
    }
    ~Network() {
#ifdef _WIN32
        WSACleanup();
#endif
    }
};
struct SocketGuard {
    Socket fd;
    explicit SocketGuard(Socket s): fd(s) {}
    ~SocketGuard() { if (fd != badSocket) closeSocket(fd); }
    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;
};
std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    return a == std::string::npos ? "" : s.substr(a, s.find_last_not_of(" \t\r\n") - a + 1);
}
int number(const std::string& s, int lo, int hi) {
    std::string t = trim(s);
    if (t.empty() || t.find_first_not_of("0123456789") != std::string::npos)
        throw std::runtime_error("Expected a whole number: " + t);
    size_t end = 0;
    long n = std::stol(t, &end);
    if (end != t.size() || n < lo || n > hi) throw std::runtime_error("Number out of range: " + t);
    return static_cast<int>(n);
}
std::vector<std::string> split(const std::string& s) {
    std::vector<std::string> v;
    size_t start = 0, p;
    while ((p = s.find('|', start)) != std::string::npos) {
        v.push_back(trim(s.substr(start, p-start))); start = p+1;
    }
    v.push_back(trim(s.substr(start))); return v;
}
std::string timeText(const char* format) {
    std::time_t t = std::time(NULL);
    std::tm tmValue;
#ifdef _WIN32
    localtime_s(&tmValue, &t);
#else
    localtime_r(&t, &tmValue);
#endif
    char buf[80]; std::strftime(buf, sizeof(buf), format, &tmValue); return buf;
}
std::string dec(double n) { std::ostringstream s; s << std::fixed << std::setprecision(2) << n; return s.str(); }
std::string csv(std::string s) {
    // Neutralize spreadsheet formulas in exported user-controlled text.
    if (!s.empty() && std::string("=+-@\t\r").find(s[0]) != std::string::npos) s = "'" + s;
    std::string out = "\"";
    for (char c: s) { if (c == '"') out += '"'; out += c; }
    return out + '"';
}
struct Target {
    std::string name, ip;
    int port, timeout, slow, failures;
};
Target parseTarget(const std::string& line) {
    auto v = split(line);
    if (v.size() != 6) throw std::runtime_error("Use name|IPv4|port|timeout_ms|slow_ms|failures");
    if (v[0].empty() || v[0].size() > 32) throw std::runtime_error("Name must be 1-32 characters.");
    for (unsigned char c: v[0]) if (c < 32 || c > 126) throw std::runtime_error("Use printable ASCII names.");
    in_addr addr;
    if (inet_pton(AF_INET, v[1].c_str(), &addr) != 1) throw std::runtime_error("Enter a numeric IPv4 address, not a URL or hostname.");
    unsigned long ip = ntohl(addr.s_addr);
    if (ip == 0 || (ip >> 24) == 0 || (ip >> 24) >= 224)
        throw std::runtime_error("Use a unicast IPv4 address.");
    Target t = {v[0], v[1], number(v[2],1,65535), number(v[3],100,10000), number(v[4],1,10000), number(v[5],1,20)};
    return t;
}
void uniqueTarget(const std::vector<Target>& targets, const Target& t) {
    for (const auto& old: targets) {
        if (old.name == t.name) throw std::runtime_error("Duplicate target name.");
        if (old.ip == t.ip && old.port == t.port) throw std::runtime_error("Duplicate IP and port.");
    }
}
std::vector<Target> loadTargets(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("Cannot open " + path + ". Run from the extracted project folder.");
    std::vector<Target> result; std::string line; int n = 0;
    while (std::getline(f,line)) {
        ++n; line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        try { Target t = parseTarget(line); uniqueTarget(result,t); result.push_back(t); }
        catch (const std::exception& e) { throw std::runtime_error(path + ": line " + std::to_string(n) + ": " + e.what()); }
        if (result.size() > 64) throw std::runtime_error("Maximum 64 configured services.");
    }
    if (f.bad()) throw std::runtime_error("Failed reading targets.");
    return result;
}
void replaceFile(const std::string& tmp, const std::string& dest) {
#ifdef _WIN32
    if (!MoveFileExA(tmp.c_str(),dest.c_str(),MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        throw std::runtime_error("Cannot replace " + dest + ". Close it in other applications.");
#else
    if (std::rename(tmp.c_str(),dest.c_str())) throw std::runtime_error("Cannot replace " + dest);
#endif
}
void finish(std::ofstream& f) { f.flush(); if (!f) throw std::runtime_error("Write failed: check free space and permissions."); f.close(); if (!f) throw std::runtime_error("File close failed."); }
void saveTargets(const std::string& path, const std::vector<Target>& targets) {
    std::ofstream f(path + ".tmp");
    if (!f) throw std::runtime_error("Cannot write configuration.");
    f << "# name|IPv4|port|timeout_ms|slow_ms|consecutive_failures\n";
    for (const auto& t: targets) f << t.name << '|' << t.ip << '|' << t.port << '|' << t.timeout << '|' << t.slow << '|' << t.failures << '\n';
    finish(f); replaceFile(path + ".tmp",path);
}
void makeDir(const std::string& path) {
#ifdef _WIN32
    int r = _mkdir(path.c_str());
#else
    int r = mkdir(path.c_str(),0755);
#endif
    if (r != 0 && errno != EEXIST) throw std::runtime_error("Cannot create directory: " + path);
}
std::string errorName(int e) {
#ifdef _WIN32
    if (e == WSAECONNREFUSED) return "REFUSED";
    if (e == WSAETIMEDOUT) return "TIMEOUT";
    if (e == WSAENETUNREACH || e == WSAEHOSTUNREACH) return "UNREACHABLE";
#else
    if (e == ECONNREFUSED) return "REFUSED";
    if (e == ETIMEDOUT) return "TIMEOUT";
    if (e == ENETUNREACH || e == EHOSTUNREACH) return "UNREACHABLE";
#endif
    return "SOCKET_ERROR_" + std::to_string(e);
}
struct Probe { bool ok = false; double ms = 0; std::string detail = "NOT_CHECKED"; };
Probe probe(const Target& t) {
    Probe result;
    SocketGuard sock(::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP));
    if (sock.fd == badSocket) { result.detail = errorName(socketError()); return result; }
#ifdef _WIN32
    u_long mode = 1;
    if (ioctlsocket(sock.fd,FIONBIO,&mode) != 0) { result.detail = errorName(socketError()); return result; }
#else
    if (sock.fd >= FD_SETSIZE) { result.detail = "LOCAL_FD_LIMIT"; return result; }
    int flags = fcntl(sock.fd,F_GETFL,0);
    if (flags == -1 || fcntl(sock.fd,F_SETFL,flags|O_NONBLOCK) == -1) { result.detail = errorName(socketError()); return result; }
#endif
    sockaddr_in address = {};
    address.sin_family = AF_INET; address.sin_port = htons(static_cast<unsigned short>(t.port));
    inet_pton(AF_INET,t.ip.c_str(),&address.sin_addr);
    auto start = Clock::now();
    int c = connect(sock.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address));
    if (c == 0) { result.ok = true; result.detail = "CONNECTED"; }
    else {
        int e = socketError();
        if (!pending(e)) result.detail = errorName(e);
        else {
            fd_set writeSet, errorSet;
            FD_ZERO(&writeSet); FD_ZERO(&errorSet); FD_SET(sock.fd,&writeSet); FD_SET(sock.fd,&errorSet);
            timeval tv; tv.tv_sec = t.timeout/1000; tv.tv_usec = (t.timeout%1000)*1000;
#ifdef _WIN32
            int ready = select(0,NULL,&writeSet,&errorSet,&tv);
#else
            int ready = select(sock.fd+1,NULL,&writeSet,&errorSet,&tv);
#endif
            if (ready == 0) result.detail = "TIMEOUT";
            else if (ready < 0) result.detail = errorName(socketError());
            else {
                int soError = 0;
#ifdef _WIN32
                int len = sizeof(soError);
#else
                socklen_t len = sizeof(soError);
#endif
                if (getsockopt(sock.fd,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&soError),&len) != 0) result.detail = errorName(socketError());
                else if (soError != 0) result.detail = errorName(soError);
                else { result.ok = true; result.detail = "CONNECTED"; }
            }
        }
    }
    result.ms = std::chrono::duration<double,std::milli>(Clock::now()-start).count();
    return result;
}
struct Stats {
    unsigned long checks = 0, successes = 0;
    int streak = 0;
    double total = 0, minimum = 0, maximum = 0;
    std::string state = "UNKNOWN";
    Probe last;
    void update(const Target& t, const Probe& p) {
        last = p; ++checks;
        if (p.ok) {
            ++successes; streak = 0; total += p.ms;
            minimum = successes == 1 ? p.ms : std::min(minimum,p.ms);
            maximum = std::max(maximum,p.ms);
            state = p.ms > t.slow ? "SLOW" : "UP";
        } else {
            ++streak;
            state = streak >= t.failures ? "ALERT" : "SUSPECT";
        }
    }
};
void appendCsv(const std::string& path, const std::string& header, const std::string& row) {
    std::ifstream existing(path,std::ios::binary);
    bool empty = !existing || existing.peek() == std::ifstream::traits_type::eof(); existing.close();
    std::ofstream f(path,std::ios::app);
    if (!f) throw std::runtime_error("Cannot append to " + path);
    if (empty) f << header << '\n';
    f << row << '\n'; finish(f);
}
void report(const std::string& path, const std::vector<Target>& targets, const std::vector<Stats>& stats) {
    std::ofstream f(path + ".tmp");
    if (!f) throw std::runtime_error("Cannot write session report.");
    f << "name,ipv4,port,state,checks,successful_checks,failed_checks,success_percent,min_connect_ms,avg_connect_ms,max_connect_ms,last_result\n";
    for (size_t i=0;i<targets.size();++i) {
        const auto& t=targets[i]; const auto& s=stats[i];
        f << csv(t.name) << ',' << csv(t.ip) << ',' << t.port << ',' << s.state << ',' << s.checks << ',' << s.successes << ',' << s.checks-s.successes << ',';
        f << (s.checks ? dec(100.0*s.successes/s.checks) : "") << ',';
        f << (s.successes ? dec(s.minimum) : "") << ',' << (s.successes ? dec(s.total/s.successes) : "") << ',' << (s.successes ? dec(s.maximum) : "") << ',' << csv(s.last.detail) << '\n';
    }
    finish(f); replaceFile(path + ".tmp",path);
}
void banner() {
    std::cout << "\n============================================================\n"
              << "                  NETWATCH PRO 1.0\n"
              << " Coded by Cyber Security Engineer Mr Sabaz Ali Khan\n"
              << "============================================================\n"
              << " TCP service monitoring | IPv4 | Local CSV history\n"
              << " Monitor devices and services you own or may administer.\n\n";
}
void list(const std::vector<Target>& targets) {
    std::cout << "Configured services: " << targets.size() << "\n";
    for (size_t i=0;i<targets.size();++i) {
        const auto& t=targets[i];
        std::cout << i+1 << ". " << t.name << "  " << t.ip << ':' << t.port << "  timeout=" << t.timeout << "ms slow=" << t.slow << "ms failures=" << t.failures << '\n';
    }
}
void monitor(const std::vector<Target>& targets, int cycles, int interval, int workers, const std::string& out, bool bell) {
    if (targets.empty()) throw std::runtime_error("No targets. Add a service first.");
    makeDir(out); makeDir(out+"/logs"); makeDir(out+"/reports");
    std::string session = timeText("%Y%m%d_%H%M%S") + "_" + std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(Clock::now().time_since_epoch()).count());
    std::string reportPath = out+"/reports/session_"+session+".csv";
    std::vector<Stats> stats(targets.size());
    stopped = 0;
    std::cout << "Ctrl+C stops monitoring and returns to the menu (if interactive).\n";
    for (int cycle=1; !stopped && (cycles == 0 || cycle <= cycles); ++cycle) {
        std::vector<Probe> results(targets.size());
        std::atomic<size_t> next(0);
        std::vector<std::thread> pool;
        // Join already-created threads even if resource exhaustion prevents creation.
        try {
            for (size_t w=0;w<std::min(targets.size(),static_cast<size_t>(workers));++w) pool.emplace_back([&] {
                for (;;) { size_t i=next.fetch_add(1); if(i>=targets.size()) break; results[i]=probe(targets[i]); }
            });
        } catch (...) { for (auto& th: pool) th.join(); throw; }
        for (auto& th: pool) th.join();
        std::string timestamp=timeText("%Y-%m-%d %H:%M:%S"), day=timeText("%Y-%m-%d");
        std::cout << "\n" << timestamp << " | Cycle " << cycle << "\n";
        std::cout << std::left << std::setw(25) << "SERVICE" << std::setw(11) << "STATE" << std::setw(13) << "CONNECT ms" << std::setw(13) << "SUCCESS %" << "RESULT\n";
        for (size_t i=0;i<targets.size();++i) {
            const auto& t=targets[i]; auto& s=stats[i]; const auto& p=results[i];
            std::string previous=s.state; s.update(t,p);
            std::string common=csv(timestamp)+','+csv(session)+','+csv(t.name)+','+csv(t.ip)+','+std::to_string(t.port)+',';
            appendCsv(out+"/logs/checks_"+day+".csv", "timestamp_local,session,name,ipv4,port,state,result,attempt_ms,connected", common+s.state+','+p.detail+','+dec(p.ms)+','+(p.ok?"1":"0"));
            if(previous != s.state) {
                appendCsv(out+"/logs/events_"+day+".csv", "timestamp_local,session,name,ipv4,port,previous_state,new_state,result",common+previous+','+s.state+','+p.detail);
                if(bell && (s.state=="ALERT" || s.state=="SLOW")) std::cout << '\a';
            }
            std::cout << std::left << std::setw(25) << t.name.substr(0,24) << std::setw(11) << s.state << std::setw(13) << (p.ok?dec(p.ms):"--") << std::setw(13) << dec(100.0*s.successes/s.checks) << p.detail << '\n';
            if(previous != s.state && previous != "UNKNOWN") std::cout << "  Event: " << t.name << " " << previous << " -> " << s.state << '\n';
        }
        report(reportPath,targets,stats);
        std::cout << "ALERT means TCP service check failed; device may still be online.\n";
        std::cout.flush();
        if(cycles && cycle>=cycles) break;
        for(int tick=0;tick<interval*10 && !stopped;++tick) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    std::cout << "\nSession report: " << reportPath << "\nDaily history: " << out << "/logs/\n";
}
std::string ask(const std::string& prompt) {
    std::cout << prompt; std::string s;
    if(!std::getline(std::cin,s)) throw std::runtime_error("Input closed.");
    return trim(s);
}
void help() {
    std::cout << "Usage: NetWatchPro [--once | --watch | --cycles N | --list] [options]\n"
    << "No action: interactive menu. --cycles 0: continuous monitoring.\n"
    << "  --config PATH   Target file (default targets.conf)\n"
    << "  --out PATH      Output folder (default output; parent must exist)\n"
    << "  --interval N    Wait 1-3600 seconds after each cycle (default 5)\n"
    << "  --workers N     Concurrent checks, 1-16 (default 4)\n"
    << "  --bell          Terminal bell on entering ALERT or SLOW\n"
    << "  --help          Show this help\n"
    << "Checks TCP connections, not ICMP, packet loss, TLS or HTTP health.\n"
    << "Only numeric IPv4 targets are supported. No administrator rights needed.\n";
}
int main(int argc, char** argv) {
    try {
        Network network; std::signal(SIGINT,stopSignal); std::signal(SIGTERM,stopSignal);
        std::string config="targets.conf", out="output", action="menu";
        int cycles=0, interval=5, workers=4; bool bell=false;
        for(int i=1;i<argc;++i) {
            std::string a=argv[i];
            if(a=="--help" || a=="-h") { help(); return 0; }
            if(a=="--once" || a=="--watch" || a=="--list" || a=="--cycles") {
                if(action!="menu") throw std::runtime_error("Choose only one action.");
                action = a=="--list" ? "list" : "monitor";
                if(a=="--once") cycles=1;
                else if(a=="--cycles") { if(++i>=argc) throw std::runtime_error("Missing cycles."); cycles=number(argv[i],0,1000000); }
            } else if(a=="--bell") bell=true;
            else if(a=="--config" || a=="--out" || a=="--interval" || a=="--workers") {
                if(++i>=argc) throw std::runtime_error("Missing value for " + a);
                if(a=="--config") config=argv[i];
                else if(a=="--out") { out=argv[i]; if(out.empty()) throw std::runtime_error("Empty output path."); }
                else if(a=="--interval") interval=number(argv[i],1,3600);
                else workers=number(argv[i],1,16);
            } else throw std::runtime_error("Unknown argument: " + a);
        }
        banner();
        if(action!="menu") {
            auto targets=loadTargets(config);
            if(action=="list") list(targets); else monitor(targets,cycles,interval,workers,out,bell);
            return 0;
        }
        while(true) {
            std::cout << "\n1. List services\n2. Add service\n3. Remove service\n4. Check once\n5. Monitor continuously\n6. Monitor fixed cycles\n7. Help\n0. Exit\n";
            std::string choice=ask("Select: ");
            if(choice=="0") break;
            try {
                if(choice=="7") { help(); continue; }
                auto targets=loadTargets(config);
                if(choice=="1") list(targets);
                else if(choice=="2") {
                    if(targets.size()>=64) throw std::runtime_error("Maximum 64 services.");
                    std::cout << "Example: Router Web|192.168.1.1|80|1500|200|3\n";
                    Target t=parseTarget(ask("name|IPv4|port|timeout_ms|slow_ms|failures: "));
                    uniqueTarget(targets,t); targets.push_back(t); saveTargets(config,targets); std::cout << "Service saved.\n";
                } else if(choice=="3") {
                    list(targets); if(targets.empty()) continue;
                    int index=number(ask("Service number (0 cancels): "),0,static_cast<int>(targets.size()));
                    if(index) { targets.erase(targets.begin()+index-1); saveTargets(config,targets); std::cout << "Service removed.\n"; }
                } else if(choice=="4" || choice=="5" || choice=="6") {
                    int n=choice=="4"?1:0;
                    if(choice=="6") n=number(ask("Cycles (1-1000000): "),1,1000000);
                    monitor(targets,n,interval,workers,out,bell);
                } else std::cout << "Choose 0-7.\n";
            } catch(const std::exception& e) { std::cerr << "Error: " << e.what() << '\n'; }
        }
        return 0;
    } catch(const std::exception& e) { std::cerr << "Error: " << e.what() << '\n'; return 1; }
}
