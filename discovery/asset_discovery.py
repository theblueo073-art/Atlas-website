import ipaddress
import socket


def validate_target(target):
    """Validate an IP address, network range or domain name."""

    target = target.strip()

    try:
        network = ipaddress.ip_network(target, strict=False)
        return {
            "target": target,
            "type": "network_range" if network.prefixlen < network.max_prefixlen else "ip_address",
            "valid": True
        }

    except ValueError:
        pass

    try:
        socket.getaddrinfo(target, None)

        return {
            "target": target,
            "type": "domain",
            "valid": True
        }

    except socket.gaierror:
        return {
            "target": target,
            "type": "unknown",
            "valid": False
        }


def resolve_domain(domain):
    """Resolve a domain into its associated IP addresses."""

    try:
        addresses = socket.getaddrinfo(domain, None)

        return list({
            address[4][0]
            for address in addresses
        })

    except socket.gaierror:
        return []


if __name__ == "__main__":
    target = input("Enter an authorized target: ")

    result = validate_target(target)

    print("\nATLAS Asset Discovery")
    print("--------------------")
    print(result)

    if result["valid"] and result["type"] == "domain":
        print("\nResolved IP addresses:")
        for ip in resolve_domain(target):
            print(f" - {ip}")