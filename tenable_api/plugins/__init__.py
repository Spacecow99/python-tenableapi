

import requests


class Plugins(requests.Session):
    """
    Tenable Plugins API
    https://www.tenable.com/plugins/api/v1/
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
        https://www.tenable.com/plugins/api/v1/all

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
        https://www.tenable.com/plugins/api/v1/all?sort=newest
        
        args:
            page (int): page number
        """
        endpoint = self.url + 'all?sort=newest' + "&page=" + str(page)
        response = requests.get(endpoint)
        return response.json()

    def updated(self, page=1):
        """
        Get updated plugins
        https://www.tenable.com/plugins/api/v1/all?sort=updated
        
        args:
            page (int): page number
        """
        endpoint = self.url + 'all?sort=updated' + "&page=" + str(page)
        response = requests.get(endpoint)
        return response.json()

    def families(self, type):
        """ 
        Get plugin families
        https://www.tenable.com/plugins/api/v1/families
        
        args:
            type (str): product type
        """
        endpoint = self.url + 'families?type=' + type
        response = requests.get(endpoint)
        return response.json()

    def family(self, type, family, page=1):
        """
        Get plugin family
        https://www.tenable.com/plugins/api/v1/families/type/family
        
        args:
            type (str): product type
            family (str): family name
            page (int): page number
        """
        endpoint = self.url + type + '/families/' + family + "?page=" + str(page)
        response = requests.get(endpoint)
        return response.json()

    def plugin(self, family, plugin_id):
        """ 
        Get plugin
        https://www.tenable.com/plugins/api/v1/families/family/plugin_id
        
        args:
            family (str): family name
            plugin_id (str): plugin id
        """
        endpoint = self.url + family + '/' + plugin_id
        response = requests.get(endpoint)
        return response.json()

    def search(self, q, page=1):
        """
        Search plugins
        https://www.tenable.com/plugins/api/v1/search
        
        args:
            q (str): query
            page (int): page number
        """
        endpoint = self.url + 'search?q=' + q + "&page=" + str(page)
        response = requests.get(endpoint)
        return response.json()
