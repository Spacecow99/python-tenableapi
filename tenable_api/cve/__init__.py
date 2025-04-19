

import re

import requests


class CVE(requests.Session):
    """
    requests.Session wrapper around CVE api endpoint.
    https://www.tenable.com/cve/api/v1/
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
        Search for CVE details.
        https://www.tenable.com/cve/api/v1/search
        
        args:
            q (str): search query
            page (int): page number
        returns:
            dict: CVE details
        """
        endpoint = self.url + 'search?q=' + q + '&page=' + str(page)
        response = requests.get(endpoint)
        return response.json()

    def newest(self, page: int = 1):
        """
        Get newest CVE details.
        https://www.tenable.com/cve/api/v1?sort=newest
        
        args:
            page (int): page number
        returns:
            dict: CVE details
        """
        endpoint = self.url + '?sort=newest' + '&page=' + str(page)
        response = requests.get(endpoint)
        return response.json()

    def updated(self, page: int = 1):
        """
        Get recently updated CVE details.
        https://www.tenable.com/cve/api/v1?sort=updated
        
        args:
            page (int): page number
        returns:
            dict: CVE details
        """
        endpoint = self.url + '?sort=updated' + '&page=' + str(page)
        response = requests.get(endpoint)
        return response.json()

    def all(self, page: int = 1):
        """
        Get all CVE details.
        https://www.tenable.com/cve/api/v1

        args:
            page (int): page number.
        returns:
            dict: CVE details
        """
        endpoint = self.url + '?page=' + str(page)
        response = requests.get(endpoint)
        return response.json()

    def cve(self, cve_id):
        """
        Get specific CVE's details.
        https://www.tenable.com/cve/api/v1/CVE-2017-0001
        
        args:
            cve_id (str): CVE ID in the format CVE-YYYY-NNNN
        Returns:
            dict: CVE details
        Raises:
            ValueError: If the CVE ID format is invalid
        """
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
            raise ValueError('Invalid CVE ID format')

        endpoint = self.url + cve_id
        response = requests.get(endpoint)
        return response.json()

    def plugins(self, cve_id):
        """
        Get CVE related plugins
        https://www.tenable.com/cve/api/v1/CVE-2017-0001/plugins
        
        args:
            cve_id (str): CVE ID in the format CVE-YYYY-NNNN
        Returns:
            dict: CVE related plugins
        Raises:
            ValueError: If the CVE ID format is invalid
        """
        if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
            raise ValueError('Invalid CVE ID format')

        endpoint = self.url + cve_id + '/plugins'
        response = requests.get(endpoint)
        return response.json()
