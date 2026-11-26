import subprocess
import xml.etree.ElementTree as ET


def scan_ports(target):
    """Scan common TCP ports on an authorized target."""

    command = [
        "nmap",
        "-sV",
        "--top-ports",
        "100",
        "-oX",
        "-",
        target
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            check=False
        )

        if result.returncode != 0:
            print("Nmap error:", result.stderr)
            return []

        root = ET.fromstring(result.stdout)
        open_ports = []

        for port in root.findall(".//port"):
            state = port.find("state")

            if state is not None and state.get("state") == "open":
                service = port.find("service")

                open_ports.append({
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "service": service.get("name", "unknown") if service is not None else "unknown",
                    "version": service.get("version", "unknown") if service is not None else "unknown"
                })

        return open_ports

    except subprocess.TimeoutExpired:
        print("Scan timed out.")
        return []

    except ET.ParseError:
        print("Unable to process Nmap results.")
        return []


if __name__ == "__main__":
    target = input("Enter an authorized IP address: ")

    results = scan_ports(target)

    print("\nATLAS PORT SCAN RESULTS")
    print("-----------------------")

    for item in results:
        print(
            f"Port: {item['port']} | "
            f"Protocol: {item['protocol']} | "
            f"Service: {item['service']} | "
            f"Version: {item['version']}"
        )

    if not results:
        print("No open ports discovered.")