

"""

"""

import requests



def format_search_query(*args):
    """
    Format search query
    args:
        args (tuple): search query
    """
    return ' AND '.join(args)


class Plugins(requests.Session):
    """
    Tenable Plugins API
    """

    def __init__(self, *args, **kwargs):
        super(Plugins, self).__init__(*args, **kwargs)
        self.url = 'https://www.tenable.com/plugins/api/v1/'
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
    
    def all(self, page=1, sort=""):
        """
        Get all plugins
        args:
            page (int): page number
            sort (str): sort by newest or updated
        """
        endpoint = self.url + 'all' + "?page=" + str(page) + "&sort=" + sort
        response = requests.get(endpoint)
        return response.json()

    def newest(self, page=1):
        """
        Get newest plugins
        args:
            page (int): page number
        """
        endpoint = self.url + 'all?sort=newest' + "&page=" + str(page)
        response = requests.get(endpoint)
        return response.json()

    def updated(self, page=1):
        """
        Get updated plugins
        args:
            page (int): page number
        """
        endpoint = self.url + 'all?sort=updated' + "&page=" + str(page)
        response = requests.get(endpoint)
        return response.json()

    def families(self, type):
        """ 
        Get plugin families
        args:
            type (str): 
        """
        endpoint = self.url + 'families?type=' + type
        response = requests.get(endpoint)
        return response.json()

    def family(self, type, family, page=1):
        """
        Get plugin family
        args:
            type (str): 
            family (str): 
            page (int): page number
        """
        endpoint = self.url + type + '/families/' + family + "?page=" + str(page)
        response = requests.get(endpoint)
        return response.json()

    def plugin(self, family, plugin_id):
        """ 
        Get plugin
        args:
            family (str): 
            plugin_id (str):
        """
        endpoint = self.url + family + '/' + plugin_id
        response = requests.get(endpoint)
        return response.json()

    def search(self, q, page=1):
        """
        Search plugins
        args:
            q (str): query
            page (int): page number
        """
        endpoint = self.url + 'search?q=' + q + "&page=" + str(page)
        response = requests.get(endpoint)
        return response.json()
