import subprocess
import ipaddress


def discover_hosts(network):
    """Discover live hosts within an authorized network."""

    try:
        ipaddress.ip_network(network, strict=True)

    except ValueError:
        print("Invalid network range.")
        return []

    command = [
        "nmap",
        "-sn",
        "-oG",
        "-",
        network
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False
        )

        if result.returncode != 0:
            print("Nmap encountered an error:")
            print(result.stderr)
            return []

        live_hosts = []

        for line in result.stdout.splitlines():
            if "Status: Up" in line:
                parts = line.split()

                if len(parts) > 1:
                    live_hosts.append(parts[1])

        return live_hosts

    except subprocess.TimeoutExpired:
        print("Host discovery timed out.")
        return []


if __name__ == "__main__":
    network = input("Enter your authorized network range: ")

    hosts = discover_hosts(network)

    print("\nATLAS HOST DISCOVERY RESULTS")
    print("----------------------------")

    if hosts:
        for host in hosts:
            print(f"[+] Live host: {host}")
    else:
        print("No live hosts discovered.")