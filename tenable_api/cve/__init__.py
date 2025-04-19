

"""

"""

import re

import requests


class CVE(requests.Session):
    """
    Tenable CVE API
    """

    def __init__(self, *args, **kwargs):
        super(CVE, self).__init__(*args, **kwargs)
        self.url = 'https://www.tenable.com/cve/api/v1/'
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

    def search(self, q: str, page: int = 1):
        """
        Search for CVEs
        args:
            q: str
            page: int
        """
        endpoint = self.url + 'search?q=' + q + '&page=' + str(page)
        response = requests.get(endpoint)
        return response.json()

    def newest(self, page: int = 1):
        """
        Get newest CVEs
        args:
            page: int
        """
        endpoint = self.url + '?sort=newest' + '&page=' + str(page)
        response = requests.get(endpoint)
        return response.json()

    def updated(self, page: int = 1):
        """
        Get updated CVEs
        args:
            page: int
        """
        endpoint = self.url + '?sort=updated' + '&page=' + str(page)
        response = requests.get(endpoint)
        return response.json()

    def all(self, page: int = 1):
        """
        Get all CVEs
        args
            page: int
        """
        endpoint = self.url + '?page=' + str(page)
        response = requests.get(endpoint)
        return response.json()

    def cve(self, cve_id):
        """
        Get CVE
        args:
            cve_id: str
        """
        # TODO: Add a check for the cve_id format
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
            raise ValueError('Invalid CVE ID format')

        endpoint = self.url + cve_id
        response = requests.get(endpoint)
        return response.json()

    def plugins(self, cve_id):
        """
        Get CVE related plugins
        args:
            cve_id: str
        """
        # TODO: Add a check for the cve_id format
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
            raise ValueError('Invalid CVE ID format')

        endpoint = self.url + cve_id + '/plugins'
        response = requests.get(endpoint)
        return response.json()
