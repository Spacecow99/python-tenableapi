

"""

"""

import requests


class AttackPathTechniques(requests.Session):
    """
    Attack Path Techniques
    """
    
    def __init__(self, *args, **kwargs):
        super(AttackPathTechniques, self).__init__(*args, **kwargs)
        self.url = 'https://www.tenable.com/attack-path-techniques/api/v1/'
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

    def all(self, page=1):
        """
        Get all attack path techniques
        args:
            page (int): page number
        """
        endpoint = self.url + "all" + "?page=" + str(page)
        response = self.get(endpoint)
        return response.json()

    def search(self, q, page=1, sort=""):
        """
        Search for attack path techniques
        args:
            q (str): search query
            page (int): page number
            sort (str): sort by
        """
        endpoint = self.url + "search?q=" + q + "&page=" + str(page) + "&sort=" + sort
        response = self.get(endpoint)
        return response.json()
