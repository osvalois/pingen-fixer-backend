import requests
from requests.auth import HTTPBasicAuth
from config import Config

class SonarClient:
    def __init__(self):
        self.auth = HTTPBasicAuth(Config.SONAR_TOKEN, '')
        self.base_url = Config.SONAR_URL

    def fetch_issues(self, project_key, additional_params={}):
        all_issues = []
        page = 1
        page_size = 500
        max_results = 10000

        while len(all_issues) < max_results:
            try:
                response = requests.get(
                    f"{self.base_url}/api/issues/search",
                    params={
                        "componentKeys": project_key,
                        "types": "BUG,VULNERABILITY,CODE_SMELL",
                        "resolved": "false",
                        "p": page,
                        "ps": page_size,
                        **additional_params
                    },
                    auth=self.auth
                )
                response.raise_for_status()
                data = response.json()
                issues = data['issues']
                all_issues.extend(issues)

                if len(issues) < page_size or len(all_issues) >= data['total']:
                    break

                page += 1
            except requests.RequestException as e:
                print(f"Error fetching issues: {str(e)}")
                break

        return all_issues

    def fetch_code_snippet(self, component, start_line, end_line):
        try:
            response = requests.get(
                f"{self.base_url}/api/sources/raw",
                params={
                    "key": component,
                    "from": start_line,
                    "to": end_line
                },
                auth=self.auth
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"Error fetching code snippet: {str(e)}")
            return None

sonar_client = SonarClient()