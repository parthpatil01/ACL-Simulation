def parse_acl_line(line):
    parts = line.split()


    if not parts:
        return None


    if "interface" in parts:
        return None


    if not "access-list" in parts:
        return None


    acl_index = parts.index("access-list")


    if acl_index + 2 >= len(parts):
        return None

    acl_number = parts[acl_index + 1]
    action = parts[acl_index + 2]

    if action not in ["permit", "deny"]:
        return None

    # Safety check for protocol
    if acl_index + 3 >= len(parts):
        return None
    protocol = parts[acl_index + 3]

    # Handle source IP and wildcard/netmask
    if acl_index + 4 >= len(parts):
        return None
    src_ip = parts[acl_index + 4]

    # Handle "any" for source
    if src_ip == "any":
        src_wildcard = "255.255.255.255"  # Full wildcard for "any"
        next_index = acl_index + 5
    else:
        # Ensure have a wildcard mask
        if acl_index + 5 >= len(parts):
            return None
        src_wildcard = parts[acl_index + 5]
        next_index = acl_index + 6

    # Check if have enough parts for destination
    if next_index >= len(parts):
        return None
    dst_ip = parts[next_index]

    # Handle "any" for destination
    if dst_ip == "any":
        dst_wildcard = "255.255.255.255"  # Full wildcard for "any"
        next_index += 1
    else:
        # Ensure have a wildcard mask for destination
        if next_index + 1 >= len(parts):
            return None
        dst_wildcard = parts[next_index + 1]
        next_index += 2

    # Check for port specification
    port_start = None
    port_end = None

    if next_index < len(parts):
        # Handle port range
        if parts[next_index] == "range":
            if next_index + 1 < len(parts):
                try:
                    # Handle format like "range 20-21"
                    if "-" in parts[next_index + 1]:
                        port_range = parts[next_index + 1].split("-")
                        port_start = int(port_range[0])
                        port_end = int(port_range[1])

                    elif next_index + 2 < len(parts):
                        port_start = int(parts[next_index + 1])
                        port_end = int(parts[next_index + 2])
                except ValueError:
                    pass
        # Handle eq
        elif parts[next_index] == "eq" and next_index + 1 < len(parts):
            try:
                port_start = int(parts[next_index + 1])
                port_end = port_start
            except ValueError:
                pass

    return {
        "acl_number": acl_number,
        "action": action,
        "protocol": protocol,
        "src_ip": src_ip,
        "src_wildcard": src_wildcard,
        "dst_ip": dst_ip,
        "dst_wildcard": dst_wildcard,
        "port_start": port_start,
        "port_end": port_end
    }


def ip_to_int(ip):
    octets = ip.split('.')
    return (int(octets[0]) << 24) + (int(octets[1]) << 16) + (int(octets[2]) << 8) + int(octets[3])


def wildcard_to_mask(wildcard):
    return (0xFFFFFFFF - ip_to_int(wildcard))


def check_ip_match(packet_ip, acl_ip, wildcard):
    if acl_ip == "any":
        return True
    mask = wildcard_to_mask(wildcard)
    return (ip_to_int(packet_ip) & mask) == (ip_to_int(acl_ip) & mask)


def evaluate_packet(packet, acl_rules):
    src_ip, dst_ip, port = packet

    for rule in acl_rules:

        if not rule:
            continue

        # Check if source IP matches
        src_match = check_ip_match(src_ip, rule["src_ip"], rule["src_wildcard"])
        if not src_match:
            continue

        # Check if destination IP matches
        dst_match = check_ip_match(dst_ip, rule["dst_ip"], rule["dst_wildcard"])
        if not dst_match:
            continue

        # Check port range
        port_in_range = True
        if rule["port_start"] is not None and rule["port_end"] is not None:
            port_in_range = (port >= rule["port_start"] and port <= rule["port_end"])
            if not port_in_range:
                continue


        return rule["action"]

    # If no rule matched, default to deny
    return "deny"


def parse_packet_line(line):
    parts = line.strip().split()
    if len(parts) < 3:
        return None
    return (parts[0], parts[1], int(parts[2]))


def main():
    # Parse ACL rules from file
    acl_rules = []
    try:
        with open('acl_extended.txt', 'r') as acl_file:
            for line in acl_file:
                line = line.strip()
                if line:  # Skip empty lines
                    rule = parse_acl_line(line)
                    if rule:
                        acl_rules.append(rule)
    except FileNotFoundError:
        print("Error: acl_extended.txt file not found.")
        return

    # Parse packets to check from file
    packets = []
    try:
        with open('packets_extended.txt', 'r') as packets_file:
            for line in packets_file:
                line = line.strip()
                if line:  # Skip empty lines
                    packet = parse_packet_line(line)
                    if packet:
                        packets.append(packet)
    except FileNotFoundError:
        print("Error: packets_extended.txt file not found.")
        return


    for packet in packets:
        src_ip, dst_ip, port = packet
        action = evaluate_packet(packet, acl_rules)
        result = "denied" if action == "deny" else "permitted"
        print(f"Packet from {src_ip} to {dst_ip} on port {port} {result}")


if __name__ == "__main__":
    main()