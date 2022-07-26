import dataclasses
import http
import logging

import requests as requests

SCAN_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains"


logger = logging.getLogger(__name__)

class VirusTotalError(Exception):
    pass


@dataclasses.dataclass
class VirusTotalAnalysis:
    reputation: int

    # stats:
    harmless: int
    malicious: int
    suspicious: int
    undetected: int

    safe: bool = False

    def __post_init__(self):
        self.safe = not any((self.suspicious, self.malicious))


class VirusTotalAdapter:
    api_key: str

    def __init__(self, token: str) -> None:
        self.api_key = token

    def scan(self, domain: str) -> VirusTotalAnalysis:
        """Requests scanning of `domain`. Returns analysis result"""

        headers = {"x-apikey": self.api_key}
        try:
            logger.info(f"Sending scan request \n url: {SCAN_DOMAIN_URL}, \n domain: {domain}, \n headers: {headers}")
            resp = requests.get(SCAN_DOMAIN_URL + "/" + domain, headers=headers)
        except Exception as e:
            raise VirusTotalError(
                f"Error making request: {e},",
                f"URL: {SCAN_DOMAIN_URL}, domain: {domain}, headers: {headers}",
            )
        if resp.status_code != http.HTTPStatus.OK:
            raise VirusTotalError(
                f"Response from VirusTotal. Unexpected status: {resp.status_code}, message: {resp.content}",
                f"URL: {SCAN_DOMAIN_URL}, domain: {domain}, headers: {headers}",
            )
        try:
            j = resp.json()
        except Exception:
            raise VirusTotalError(f"Error parsing response: {resp.content}")

        try:
            reputation = j["data"]["attributes"]["reputation"]
            stats = j["data"]["attributes"]["last_analysis_stats"]
            analysis = VirusTotalAnalysis(
                reputation=reputation,
                harmless=stats["harmless"],
                malicious=stats["malicious"],
                suspicious=stats["suspicious"],
                undetected=stats["undetected"],
            )
        except KeyError:
            raise VirusTotalError(f"Incorrect response {j}")

        return analysis
