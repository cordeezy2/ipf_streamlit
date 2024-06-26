from dora_report import FetchDataForReporting
import streamlit as st


def main(toml_file=None, ipf_token=None, ipf_url=None, ipf_ss=None, nist_api_key=None):
    fetch_data = FetchDataForReporting(toml_file_path=toml_file, ipf_token=ipf_token, ipf_url=ipf_url, ipf_ss=ipf_ss, nist_api_key=nist_api_key)
    all_intent_violations_list_df = fetch_data.fetch_intent_checks_data()
    vuls, device_backup = fetch_data.fetch_other_check_data()
    list_app_tuple = fetch_data.fetch_app_data(for_streamlit=True)
    return fetch_data.build_report(
        all_intent_violations_list_df,
        vuls,
        device_backup,
        list_app_tuple,
        for_streamlit=True
    )


uploaded_toml = st.sidebar.file_uploader(label='inputs.toml', help='Upload the inputs.toml file')
ipf_token = st.sidebar.text_input(label='IPFabric Token', help='Enter your IPFabric Token')
ipf_url = st.sidebar.text_input(label='IPFabric URL', help='Enter your IPFabric URL')
ipf_ss = st.sidebar.text_input(label='IPFabric Snapshot', help='Enter your IPFabric Snapshot UUID')
nist_api_key = st.sidebar.text_input(label='NIST API Key', help='Enter your NIST API Key')
try:
    all_devs, final_report_df = main(toml_file=uploaded_toml, ipf_token=ipf_token, ipf_url=ipf_url, ipf_ss=ipf_ss, nist_api_key=nist_api_key)
    st.write("# App Data 1")
    st.dataframe(final_report_df[0], width=5000)
    st.write("# App Data 2")
    st.dataframe(final_report_df[1])
    st.write("# All Devices")
    st.dataframe(all_devs)
except Exception as e:
    st.write("Upload a valid toml file, heres and example of a valid toml file:")
    st.write(
        """
        ```
        applications = [
    {"name" = "Internal-app", "source" = "172.16.12.60/31", "destination" = "172.16.31.60", "protocol" = "tcp", "port" = "443", "URL" = "https://app.internal/", "Comments" = "Internal app for use by users inside network"},
    {"name" = "External-app", "source" = "172.16.21.0/24", "destination" = "172.16.32.60", "protocol" = "tcp", "port" = "443", "URL" = "https://app.external.com/", "Comments" = "External-facing app for use by users coming in over VPN"}
]
# Define the checks from ipfabric to preform and the requirements to fetch the data
# Python SDK Accepts both API and Frontend endpoints
intent_checks =[
    {'unmanged_neighbors' = {'table_endpoint' = 'technology/cdp-lldp/unmanaged-neighbors', 'filter' = ''}},
    {'hardware_eol' = {'table_endpoint' = 'tables/reports/eof/summary', 'filter' = '{"endSupport": ["color", "eq", "30"]}'}},
    {'aaa'= {'table_endpoint' = 'tables/security/aaa/authorization', 'filter' = '{"primaryMethod": ["color", "eq", "20"]}'}},
    {'ntp' = {'table_endpoint' = '/tables/management/ntp/summary', 'filter' = '{"confSources": ["color", "eq", "20"], "reachableSources": ["color", "eq", "20"]}'}},
    {'snmp_summary' = {'table_endpoint' = '/technology/management/snmp/summary', 'filter' = '{"or": [{"communitiesCount": ["color", "eq", "20"]}, {"communitiesCount": ["color", "eq", "10"]}]}'}},
    {'snmp_communities' = {'table_endpoint' = '/tables/management/snmp/communities', 'filter' = '{"name": ["color", "eq", "20"]}'}},
    {'management_access' = {'table_endpoint' = 'tables/security/aaa/lines', 'filter' = '{"inTransports": ["any", "like", "telnet"]}'}},
    {'cve' = true},
    {'backups' = true}
]

ipf_snapshot = '40e3426f-877e-46ee-a48d-18868b51262d'
```
        """
    )
    st.button(label='Press here to Start with Default settings', on_click=main(
        toml_file='dora_report/inputs/inputs.toml',
        ipf_token=st.secrets["ipf_token"],
        ipf_url=st.secrets["ipf_url"],
        nist_api_key=st.secrets["nist_api_key"]
        )
   )
    st.write('')
    st.write(f"Displaying the current error:")
    st.write(f"Error: {e}")

