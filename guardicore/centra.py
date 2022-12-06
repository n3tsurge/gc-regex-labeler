import json
import requests
from datetime import datetime, timedelta

class CentraAPI(object):

    def __init__(self, management_url="", http_scheme="https", verify_tls=True):
        """
        Initializes an API object that is used
        to make consistent calls to the Guardicore Centra API
        """

        self.management_url = management_url
        self.session = requests.Session()
        self.http_scheme = http_scheme
        self.base_url = f"{self.http_scheme}://{self.management_url}"

        self.session.headers.update({
            'Content-Type': 'application/json'
        })
        self.session.verify = verify_tls

    def authenticate(self, username, password):
        """
        Authenticates to the Guardicore Centra API and 
        gets back an access_token
        """

        auth_body = {
            "username": username,
            "password": password
        }

        response = self.session.post(f"{self.base_url}/api/v3.0/authenticate", data=json.dumps(auth_body))
        if response.status_code == 200:
            data = response.json()

            # If the account in use has MFA enabled, raise a ValueError
            if '2fa_temp_token' in data:
                raise ValueError("Guardicore credentials required MFA.  Use an acccount without MFA.")

            self.session.headers.update({
                "Authorization": f"Bearer {data['access_token']}"
            })

        if response.status_code == 401:
            raise ValueError("Incorrect Guardicore username or password.")
    
    def block_ip(self, ip, rule_set, direction):
        """
        Adds an IP address to a policy rule to block
        traffic to and/or from the IP in question
        """

        if direction not in ["DESTINATION","SOURCE","BOTH"]:
            raise ValueError("direction must either be DESTINATION, SOURCE or BOTH")

        if direction in ["DESTINATION", "BOTH"]:
            data = {
                "direction": "DESTINATION",
                "reputation_type": "top_ips",
                "ruleset_name": rule_set + " | Outbound",
                "value": ip
            }
            self.session.post(f"{self.base_url}/api/v3.0/widgets/malicious-reputation-block", data=json.dumps(data))
            
        if direction in ["SOURCE", "BOTH"]:
            data = {
                "direction": "SOURCE",
                "reputation_type": "top_ips",
                "ruleset_name": rule_set + " | Inbound",
                "value": ip
            }
            self.session.post(f"{self.base_url}/api/v3.0/widgets/malicious-reputation-block", data=json.dumps(data))


    def get_incidents(self, tags=[], tag__not=["Acknowledged"], limit=500, from_hours=24):
        """
        Fetches a list of incidents from Centra UI based on
        a set of criteria
        """

        tag_list = ",".join(tags)
        tag__not = ",".join(tag__not)
        from_time = int((datetime.now() - timedelta(hours=from_hours)).timestamp()) * 1000
        to_time = int(datetime.now().timestamp()) * 1000

        url = f"{self.base_url}/api/v3.0/incidents?tag={tag_list}&tag__not={tag__not}&from_time={from_time}&to_time={to_time}&limit={limit}"
        response = self.session.get(url)
        if response.status_code == 200:
            data = response.json()
            return data['objects']
        else:
            return []

    def tag_incident(self, id, tags):
        """
        Tags an incident with user and system defined
        tags so analysts can triage a threat more 
        readily or look back as to why a threat was triaged
        the way it was 
        """

        # Assign all the tags
        for tag in tags:
            data = {
                "action": "add",
                "tag_name": tag,
                "negate_args": None,
                "ids": [id]
            }
            self.session.post(f"{self.base_url}/api/v3.0/incidents/tag", data=json.dumps(data))

    def acknowledge_incident(self, ids=[]):
        """
        Sets the Acknowledged tag on any incidents
        present in the ids variable
        """

        # Make sure this is a list
        if not isinstance(ids, list):
            raise TypeError("ids should be a list")

        data = {
            "ids": ids,
            "negate_args": None
        }
        self.session.post(f"{self.base_url}/api/v3.0/incidents/acknowledge", data=json.dumps(data))

    def get_inner(self, destination, source):
        """
        Returns the IP that is part of an incident that is actually
        the bad indicator of the traffic
        """
        if destination['is_inner'] == False:
            return destination['ip']
        else:
            return source['ip']

    def insight_query(self, action, query, agent_filter={}):
        """
        Runs a Centra Insight query and can wait for the results
        """

        api_endpoint = "/api/v3.0/agents/query"

        # Raise an error if trying to use an unsupported action value
        if action not in ["run", "preview_selection", "abort"]:
            raise ValueError("Invalid action. Must be: run, preview_selection, or abort")

        # Build the post payload
        data = {
            "action": action,
            "filter": agent_filter,
            "query": query
        }

        response = self.session.post(f"{self.base_url}{api_endpoint}", data=json.dumps(data))
        if response.status_code == 200:
            response_data = response.json()
            return response_data['id']
        else:
            return None

    def insight_query_info(self, query_id, status_only=False):
        """
        Returns information about the query ID
        Important for determining if a query is finished or not
        status_only will just return the current status
        if not set this will return the entire response from the API
        """

        api_endpoint = f"/api/v3.0/agents/query/{query_id}"

        response = self.session.get(f"{self.base_url}{api_endpoint}")
        if response.status_code == 200:
            response_data = response.json()

            if status_only:
                return response_data['status']
            else:
                return response_data
        else:
            return None


    def insight_query_results(self, query_id, limit=20, page=0):
        """
        Fetches the result of a completed Insight query
        """

        # Set the default value for to if not overridden
        offset = limit * page

        # Create an empty result set
        results = []

        api_endpoint = f"/api/v3.0/agents/query/{query_id}/results?limit={limit}&offset={offset}"

        response = self.session.get(f"{self.base_url}{api_endpoint}")
        if response.status_code == 200:
            response_data = response.json()
            results += response_data['objects']

            # Page if necessary
            if page <= round(response_data['total_count']/limit)+1:
                results += self.insight_query_results(query_id, page=response_data['current_page'])

            return results
        else:
            return None

    def insight_label_agents(self, query_id, label_key, label_value, action=""):
        """
        Assigns a label to any agent that returned a matching response in the
        query passed in :query_id:
        """

        if action not in ["preview_agents_to_label", "add_to_label"]:
            raise ValueError("Invalid action. Must be: preview_agents_to_label or add_to_label")

        api_endpoint = f"/api/v3.0/agents/query/{query_id}/label"

        label_data = {
            "action": action,
            "label_key": label_key,
            "label_value": label_value
        }

        response = self.session.post(f"{self.base_url}{api_endpoint}", data=json.dumps(label_data))
        if response.status_code == 200:
            response_data = response.json()
            return response_data
        else:
            return None

    def list_agents(self, page=0, limit=20, *args, **kwargs):
        """
        Returns a list of agents based on the criteria
        """

        offset = limit * page
        
        api_endpoint = f"/api/v3.0/agents?limit={limit}&offset={offset}"

        # Create an empty set of results
        results = []

        response = self.session.get(f"{self.base_url}{api_endpoint}")
        if response.status_code == 200:
            response_data = response.json()
            results += response_data['objects']

            # Page if necessary
            if page <= round(response_data['total_count']/limit)+1:
                results += self.list_agents(page=response_data['current_page'], limit=limit, *args, **kwargs, )

            return results
        else:
            return None

    def list_assets(self, page=0, limit=20, *args, **kwargs):
        """
        Returns a list of assets based on the criteria
        """

        offset = limit * page
        
        api_endpoint = f"/api/v3.0/assets?limit={limit}&offset={offset}"

        if 'status' in kwargs:
            api_endpoint += f"&status={kwargs['status']}"

        # Create an empty set of results
        results = []

        response = self.session.get(f"{self.base_url}{api_endpoint}")
        if response.status_code == 200:
            response_data = response.json()
            results += response_data['objects']

            # Page if necessary
            if page <= round(response_data['total_count']/limit)+1:
                results += self.list_assets(page=response_data['current_page'], limit=limit, *args, **kwargs)

            return results
        else:
            return None

    def deactivate_assets(self, component_ids: list[str]):
        """
        Deactives a number of assets
        """

        api_endpoint = "/api/v3.0/assets/deactivate"
        
        data = {
            "component_ids": ",".join(component_ids)
        }

        response = self.session.post(f"{self.base_url}{api_endpoint}", data=json.dumps(data))
        if response.status_code == 200:
            return True
        else:
            print(response.text)
            return False

    def create_static_label(self, key, value, vms):
        """
        Creates a static label and adds assets to it
        """

        api_endpoint = f"/api/v3.0/assets/labels/{key}/{value}"

        data = {
            "vms": vms
        }

        response = self.session.post(f"{self.base_url}{api_endpoint}", data=json.dumps(data))
        if response.status_code == 200:
            return True
        else:
            print(f"Endpoint: {api_endpoint}")
            print(f"Response Code: {response.status_code}")
            print(f"Response Text: {response.text}")
            print(f"Key: {key}, Value: {value}")
            #print(json.dumps(data, indent=4))
            return False
        

        
