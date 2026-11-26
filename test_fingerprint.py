from intelligence.technology_fingerprint import fingerprint_technology

target = input("Enter an authorized website or server: ")

result = fingerprint_technology(target)

print("\n========== ATLAS TECHNOLOGY FINGERPRINT ==========")

print("Target:", result["target"])
print("HTTP Status:", result["status"])

print("\nWEB SERVER:")
print(result["server"])

print("\nDETECTED TECHNOLOGIES:")

for technology in result["technologies"]:
    print(technology)

print("\nSECURITY HEADERS:")

for header, details in result["security_headers"].items():
    status = "PRESENT" if details["present"] else "MISSING"
    print(f"{header}: {status}")

if result["error"]:
    print("\nERROR:", result["error"])

print("\n==================================================")