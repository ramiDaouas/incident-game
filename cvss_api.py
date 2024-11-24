import requests
from neo4j import GraphDatabase, RoutingControl
from neo4j.exceptions import DriverError, Neo4jError

def add_cvss(cves, session):
    for cve in cves:
        # URL of the API endpoint
        url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}'

        # Send a GET request
        response = requests.get(url)

        # Check if the request was successful
        if response.status_code == 200:
            data = response.json()  # Parse the JSON response
            try:
                cvss_str = data['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['vectorString']
                base_score = data['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                base_sev = data['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity']
                # Create a VulnerabilityRating
                query = f"""
                CREATE (r:VulnerabilityRating {{key: 'urn:vuln-rating:nvd:cvss:{cve}'}})
                """
                session.run(query)
                # Set CVSS label and attributes
                query = f"""
                MATCH (r:VulnerabilityRating)
                WHERE r.key = 'urn:vuln-rating:nvd:cvss:{cve}'
                SET r:CVSS, r.cvss_vector = '{cvss_str}', r.base_score = {base_score}, r.severity = '{base_sev}'
                """
                session.run(query)
                # Create Relationship between the CVSS and the vulnerability
                query = f"""
                MATCH (r:CVSS{{key:'urn:vuln-rating:nvd:cvss:{cve}'}}), (v:Vulnerability {{cve: '{cve}'}})
                CREATE (v)-[:has_rating]->(r)
                """
                session.run(query)
            except:
                print(f'Something went wrong with CVE {cve}')
        else:
            print(f"Error {response.status_code}: {response.text}")


URI = "neo4j+s://hackatum-one.graphdatabase.ninja:443"
AUTH = ("attendee18", "1F14QJGCXY")

drv = GraphDatabase.driver(URI, auth=AUTH, max_connection_lifetime=60)
drv.database = "attendee18"
sess = drv.session()

# Test CVSS API
cves = ['']
add_cvss(cves,sess)