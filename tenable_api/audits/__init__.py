

import requests


class Audits(requests.Session):
    """
    requests.Session wrapper around Audits api endpoint.
    https://www.tenable.com/audits/api/v1/
    """
    
    def __init__(self, *args, **kwargs):
        super(Audits, self).__init__(*args, **kwargs)
        self.url = 'https://www.tenable.com/audits/api/v1/'
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

    def all(self, page=1):
        """
        Get all audits.
        https://www.tenable.com/audits/api/v1/all
        
        args:
            page (int): page number
        """
        endpoint = self.url + "all" + "?page=" + str(page)
        response = self.get(endpoint)
        return response.json()

    def newest(self, page=1):
        """
        Get newest audits
        https://www.tenable.com/audits/api/v1/all?sort=newest
        
        args:
            page (int): page number
        """
        endpoint = self.url + "all?sort=newest" + "&page=" + str(page)
        response = self.get(endpoint)
        return response.json()

    def updates(self, page=1):
        """
        Get updated audits
        https://www.tenable.com/audits/api/v1/all?sort=updates
        
        args:
            page (int): page number
        """
        endpoint = self.url + "all?sort=updates" + "&page=" + str(page)
        response = self.get(endpoint)
        return response.json()

    def search(self, q, page=1):
        """
        Search for audits
        https://www.tenable.com/audits/api/v1/all?q=search
        
        args:
            q (str): search query
            page (int): page number
        """
        endpoint = self.url + "all?q=" + q + "&page=" + str(page)
        response = self.get(endpoint)
        return response.json()

    def references(self, page=1):
        """
        Get references
        https://www.tenable.com/audits/api/v1/references
        
        args:
            page (int): page number
        """
        endpoint = self.url + "references" + "?page=" + str(page)
        response = self.get(endpoint)
        return response.json()

    def authorities(self, page=1):
        """
        Get authorities
        https://www.tenable.com/audits/api/v1/authorities

        args:
            page (int): page number
        """
        endpoint = self.url + "authorities" + "?page=" + str(page)
        response = self.get(endpoint)
        return response.json()
