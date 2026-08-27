import requests

ghsa_id = "GHSA-45rx-2jwx-cxfr"

url = f"https://api.github.com/advisories/{ghsa_id}"

response = requests.get(
    url,
    headers={
        "Accept": "application/vnd.github+json"
    }
)

response.raise_for_status()

data = response.json()

print("GHSA:", data["ghsa_id"])
print("CVE:", data.get("cve_id"))