from neo4j import GraphDatabase, RoutingControl
from neo4j.exceptions import DriverError, Neo4jError


# Get systems affected with a certain CVE (in this case, it's just CVE-1900-8033)
def get_affected_systems(session, cve='CVE-1900-8033'):
    # Seperate queries for reference
    # POC: checking that a software version is vulnearble by comparing to a min and a max affected version
    query_desktop = """
    MATCH (s:System)-[:related_software]->(i:SoftwareInstallation) 
    WHERE toLower(i.publisher) = 'docker' and i.product='desktop'
    WITH s,i, SPLIT(i.version, ".") AS versionParts,
        SPLIT('4.10.1', ".") AS minParts,
        SPLIT('4.34.2', ".") AS maxParts
    WITH s,i, versionParts, minParts, maxParts,
        TOINTEGER(versionParts[0]) AS major, 
        TOINTEGER(versionParts[1]) AS minor, 
        TOINTEGER(versionParts[2]) AS patch,
        TOINTEGER(minParts[0]) AS minMajor, 
        TOINTEGER(minParts[1]) AS minMinor, 
        TOINTEGER(minParts[2]) AS minPatch,
        TOINTEGER(maxParts[0]) AS maxMajor, 
        TOINTEGER(maxParts[1]) AS maxMinor, 
        TOINTEGER(maxParts[2]) AS maxPatch
    WITH s,i, major, minor, patch, minMajor, minMinor, minPatch, maxMajor, maxMinor, maxPatch,
        major >= minMajor AND major <= maxMajor AS majorInRange,
        (major = minMajor AND minor >= minMinor) OR (major > minMajor) AND (major < maxMajor OR (major = maxMajor AND minor <= maxMinor)) AS minorInRange,
        (minor = minMinor AND patch >= minPatch) OR (major > minMajor AND minor > minMinor) OR (major = maxMajor AND minor = maxMinor AND patch <= maxPatch) AS patchInRange
    WHERE majorInRange AND minorInRange AND patchInRange
    RETURN s"""
    # Hardcoded and simplified min and max versions according to observations done on the graph
    query_cli = """
    MATCH (s:System)-[:related_software]->(i:SoftwareInstallation) 
    WHERE toLower(i.publisher) = 'docker' and i.product='Docker CLI' and 23 <= tointeger(i.version) <= 26
    return s"""
    query_engine = """
    MATCH (s:System)-[:related_software]->(i:SoftwareInstallation) 
    WHERE toLower(i.publisher) = 'docker' and i.product='Docker Engine' and 23 <= tointeger(i.version) <= 26
    return s"""

    # Union query makes sure that we don't get duplicates
    union_query = """
    MATCH (s:System)-[:related_software]->(i:SoftwareInstallation) 
    WHERE toLower(i.publisher) = 'docker' and i.product='desktop'
    WITH s,i, SPLIT(i.version, ".") AS versionParts,
        SPLIT('4.10.1', ".") AS minParts,
        SPLIT('4.34.2', ".") AS maxParts
    WITH s,i, versionParts, minParts, maxParts,
        TOINTEGER(versionParts[0]) AS major, 
        TOINTEGER(versionParts[1]) AS minor, 
        TOINTEGER(versionParts[2]) AS patch,
        TOINTEGER(minParts[0]) AS minMajor, 
        TOINTEGER(minParts[1]) AS minMinor, 
        TOINTEGER(minParts[2]) AS minPatch,
        TOINTEGER(maxParts[0]) AS maxMajor, 
        TOINTEGER(maxParts[1]) AS maxMinor, 
        TOINTEGER(maxParts[2]) AS maxPatch
    WITH s,i, major, minor, patch, minMajor, minMinor, minPatch, maxMajor, maxMinor, maxPatch,
        major >= minMajor AND major <= maxMajor AS majorInRange,
        (major = minMajor AND minor >= minMinor) OR (major > minMajor) AND (major < maxMajor OR (major = maxMajor AND minor <= maxMinor)) AS minorInRange,
        (minor = minMinor AND patch >= minPatch) OR (major > minMajor AND minor > minMinor) OR (major = maxMajor AND minor = maxMinor AND patch <= maxPatch) AS patchInRange
    WHERE majorInRange AND minorInRange AND patchInRange
    RETURN s
    UNION
    MATCH (s:System)-[:related_software]->(i:SoftwareInstallation) 
    WHERE toLower(i.publisher) = 'docker' and i.product='Docker CLI' and 23 <= tointeger(i.version) <= 26
    return s
    UNION
    MATCH (s:System)-[:related_software]->(i:SoftwareInstallation) 
    WHERE toLower(i.publisher) = 'docker' and i.product='Docker Engine' and 23 <= tointeger(i.version) <= 26
    return s"""
    result = session.run(union_query)
    return [record.data()['s'] for record in result]

def get_related_nodes(session, node_id=235922501, relationship='has_agent', target_node_label='EDRAgent', direction='out'):
    if direction == 'out':
        query = f"""
        MATCH (n)-[{relationship}]->(t: {target_node_label})
        WHERE n.id = {node_id}
        RETURN t
        """
    elif direction == 'in':
        query = f"""
        MATCH (n)<-[{relationship}]-(t: {target_node_label})
        WHERE n.id = {node_id}
        RETURN t
        """

    result = session.run(query)
    return [record.data()['t'] for record in result]

def get_vulnerbility_cvss_data(session, cve):
    query = f"""
    match (v:Vulnerability)-[:has_rating]->(r:CVSS)
    where v.cve='{cve}'
    return r
    """
    result = session.run(query)
    return [record.data()['r'] for record in result]

def get_vulnerbility_epss_data(session, cve):
    query = f"""
    match (v:Vulnerability)-[:has_rating]->(r:EPSS)
    where v.cve='{cve}'
    return r
    """
    result = session.run(query)
    return [record.data()['r'] for record in result]

# Get the respective risk for each affected system
def get_risk(session, system, cve):
    # Vulnearbility related metrics
    cvss_data = get_vulnerbility_cvss_data(session,cve)
    base_cvss_score = get_vulnerbility_cvss_data(session,cve)[0]['base_score'] if len(cvss_data) > 0 else 0
    epss_score = get_vulnerbility_epss_data(sess, 'CVE-1900-8033')[0]['score']
    # System related metrics
    match system['type']:
        case 'Server':
            system_type_score = 3
        case 'Network':
             system_type_score = 3
        case 'Client':
             system_type_score = 2
        case 'Unknown':
             system_type_score = 1
    provider_score = 1 if system['provider_name'].lower() != 'siemens' else 0
    state_score = 0 if system['state'].lower() == 'active' else 1
    criticality_score = 1 if system['critical'] == 1 else 0
    # check EDR
    res = get_related_nodes(session, system['id'], 'has_agent', 'EDRAgent', 'out')
    edr_score = 0 if len(res) > 0 else 1
    # check assigned roles
    res = get_related_nodes(session, system['id'], 'assigned_for', 'AssignedSystemRole', 'in')
    for result in res:
        if 'category' in result.keys() and result['category'] == 'Cybersecurity-related':
            role_score = 1
            break
        else:
            role_score = 0

    risk_sum =  (base_cvss_score/10) + (epss_score) + (criticality_score) + (system_type_score/3) + \
                (edr_score) + (provider_score) + (state_score) + (role_score)
    # Return a normalized value between 0 and 1
    return risk_sum / 8

if __name__ == '__main__':
    URI = "neo4j+s://hackatum-one.graphdatabase.ninja:443"
    AUTH = ("attendee18", "1F14QJGCXY")

    drv = GraphDatabase.driver(URI, auth=AUTH, max_connection_lifetime=60)
    drv.database = "attendee18"
    sess = drv.session()

    # Get affected systems
    affected_systems = get_affected_systems(sess)
    # Calculate the risk for each system
    a = [get_risk(sess, system, 'CVE-1900-8033') for system in affected_systems]