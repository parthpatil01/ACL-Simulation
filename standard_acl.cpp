#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <bitset>
#include <thread>
#include <mutex>
#include <netinet/in.h>
#include <arpa/inet.h>

std::mutex print_mutex;

struct ACLRule {
    std::string action;
    in_addr source_ip;
    in_addr subnet_mask;
};

in_addr wildcard_to_subnet_mask(const std::string& wildcard) {
    in_addr mask{};
    std::istringstream iss(wildcard);
    std::string token;
    int i = 0;

    while (std::getline(iss, token, '.')) {
        mask.s_addr |= ((255 - std::stoi(token)) << (24 - 8 * i));
        i++;
    }
    mask.s_addr = htonl(mask.s_addr);
    return mask;
}

std::vector<ACLRule> parse_acl(const std::string& filename) {
    std::vector<ACLRule> rules;
    std::ifstream file(filename);
    std::string line;

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string acl, list, action, ip_str, wildcard;
        iss >> acl >> list >> action >> ip_str;

        in_addr ip{}, mask{};
        if (ip_str == "any") {
            inet_aton("0.0.0.0", &ip);
            inet_aton("0.0.0.0", &mask);
        } else {
            iss >> wildcard;
            inet_aton(ip_str.c_str(), &ip);
            mask = wildcard_to_subnet_mask(wildcard);
        }
        rules.push_back({action, ip, mask});
    }

    return rules;
}

bool matches_rule(const in_addr& ip, const ACLRule& rule) {
    uint32_t ip_net = ntohl(ip.s_addr);
    uint32_t rule_ip = ntohl(rule.source_ip.s_addr);
    uint32_t mask = ntohl(rule.subnet_mask.s_addr);

    return (ip_net & mask) == (rule_ip & mask);
}

void process_packet(const std::string& ip_str, const std::vector<ACLRule>& rules) {
    in_addr ip{};
    inet_aton(ip_str.c_str(), &ip);
    bool permitted = false;
    bool matched = false;

    for (const auto& rule : rules) {
        if (matches_rule(ip, rule)) {
            permitted = (rule.action == "permit");
            matched = true;
            break;
        }
    }

    std::lock_guard<std::mutex> lock(print_mutex);
    if (!matched || !permitted) {
        std::cout << "Packet from " << ip_str << " denied\n";
    } else {
        std::cout << "Packet from " << ip_str << " permitted\n";
    }
}

void simulate_packet_flow(const std::vector<ACLRule>& rules, const std::string& packet_file) {
    std::ifstream file(packet_file);
    std::string line;
    std::vector<std::thread> threads;

    while (std::getline(file, line)) {
        threads.emplace_back(process_packet, line, std::cref(rules));
    }

    for (auto& t : threads) {
        t.join();
    }
}

int main() {
    auto rules = parse_acl("acl_standard.txt");
    simulate_packet_flow(rules, "packets_standard.txt");
    return 0;
}
