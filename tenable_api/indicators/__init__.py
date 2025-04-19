

"""

"""

import requests


class Indicators(requests.Session):
    """
    Tenable Indicators API
    """

    def __init__(self, *args, **kwargs):
        super(Indicators, self).__init__(*args, **kwargs)
        self.url = 'https://www.tenable.com/indicators/api/v1/'
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
    
    def search(self, q, page: int = 1):
        """
        Search for indicators
        args:
            q: str: query
            page: int: page number
        """
        endpoint = self.url + 'search?q=' + q + '&page=' + str(page)
        response = requests.get(endpoint)
        return response.json()

    def ioa(self, page: int = 1):
        """
        Get indicators of attack
        args:
            page: int: page number
        """
        endpoint = self.url + 'ioa?page=' + str(page)
        response = requests.get(endpoint)
        return response.json()

    def ioe(self, page: int = 1):
        """ 
        Get indicators of exposure
        args:
            page: int: page number
        """
        endpoint = self.url + 'ioe?page=' + str(page)
        response = requests.get(endpoint)
        return response.json()
