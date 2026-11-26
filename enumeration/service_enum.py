import subprocess
import xml.etree.ElementTree as ET


def enumerate_services(target):
    """Identify services and versions on an authorized target."""

    command = [
        "nmap",
        "-sV",
        "-sT",
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
            timeout=300,
            check=False
        )

        if result.returncode != 0:
            print("Nmap error:", result.stderr)
            return []

        root = ET.fromstring(result.stdout)
        services = []

        for port in root.findall(".//port"):
            state = port.find("state")

            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")

            if service is not None:
                services.append({
                    "port": port.get("portid"),
                    "protocol": port.get("protocol"),
                    "service": service.get("name", "unknown"),
                    "product": service.get("product", "unknown"),
                    "version": service.get("version", "unknown"),
                    "extra_info": service.get("extrainfo", "")
                })

        return services

    except subprocess.TimeoutExpired:
        print("Service enumeration timed out.")
        return []

    except ET.ParseError:
        print("Unable to process Nmap results.")
        return []


if __name__ == "__main__":
    target = input("Enter an authorized target IP: ")

    results = enumerate_services(target)

    print("\nATLAS SERVICE ENUMERATION RESULTS")
    print("---------------------------------")

    for item in results:
        print(
            f"Port: {item['port']} | "
            f"Service: {item['service']} | "
            f"Product: {item['product']} | "
            f"Version: {item['version']}"
        )

    if not results:
        print("No identifiable services found.")