import ipaddress

def wildcard_to_subnet_mask(wildcard):
    wildcard_parts = wildcard.split('.')
    subnet_mask_parts = []
    for part in wildcard_parts:
        subnet_mask_parts.append(str(255 - int(part)))
    return '.'.join(subnet_mask_parts)

def parse_acl(acl_file):
    acl_rules = []
    with open(acl_file, 'r') as file:
        for line in file:
            line = line.strip()
            if line.startswith("access-list"):
                parts = line.split()
                action = parts[2]  # permit or deny
                source_ip = parts[3]  # source IP
                # Handle 'any' keyword
                if source_ip == "any":
                    source_ip = "0.0.0.0"
                    subnet_mask = "0.0.0.0"  # Matches all IPs
                else:
                    wildcard = parts[4]  # wildcard mask
                    subnet_mask = wildcard_to_subnet_mask(wildcard)
                acl_rules.append((action, source_ip, subnet_mask))
    return acl_rules

def matches_acl_rule(ip, rule):
    source_ip = rule[1]
    subnet_mask = rule[2]
    # Convert to network address
    network = ipaddress.IPv4Network(f"{source_ip}/{subnet_mask}", strict=False)
    return ipaddress.IPv4Address(ip) in network

def process_packets(acl_rules, packets_file):
    with open(packets_file, 'r') as file:
        for line in file:
            source_ip = line.strip()
            permitted = None
            for rule in acl_rules:
                if matches_acl_rule(source_ip, rule):
                    if rule[0] == "permit":
                        permitted = True
                    else:
                        permitted = False
                    break  # First match applies
            # If no rule matches, deny by default
            if permitted is None:
                permitted = False
            if permitted:
                print(f"Packet from {source_ip} permitted")
            else:
                print(f"Packet from {source_ip} denied")


acl_rules = parse_acl("acl_standard.txt")
process_packets(acl_rules, "packets_standard.txt")