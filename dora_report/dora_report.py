from ipfabric import IPFClient
from ipfabric.diagrams import Unicast
import tomllib
from ipfabric.tools import Vulnerabilities
from ipfabric.tools import DeviceConfigs
import pandas as pd
import streamlit as st


class FetchDataForReporting:
    def __init__(self, toml_file_path=None, ipf_token=None, ipf_url=None, ipf_ss=None, nist_api_key=None):
        self.toml_file_path = 'inputs/inputs.toml'
        if toml_file_path:
            self.toml_file_path = toml_file_path
        if 'getvalue' in dir(self.toml_file_path):
            self.toml_data = tomllib.loads(self.toml_file_path.getvalue().decode())
        else:
            with open(self.toml_file_path, 'rb') as fp:
                self.toml_data = tomllib.load(fp)
        ipf_snapshot = ipf_ss or self.toml_data['ipf_snapshot']
        self.nist_api_key = nist_api_key or self.toml_data['nist_api_key']
        self.ipf = IPFClient(
            snapshot_id=ipf_snapshot,
            auth=ipf_token or self.toml_data['ipf_token'],
            base_url=ipf_url or self.toml_data['ipf_url']
        )
        self.ipf_columns_to_fetch = ['sn', 'version', 'hostname', 'model', 'vendor', 'siteName']

    def fetch_intent_checks_data(self):
        list_of_intent_dfs = list()
        for get_intent_conf in self.toml_data['intent_checks']:
            for intent_name, table_config in get_intent_conf.items():
                if isinstance(table_config, dict):
                    df = self.ipf.fetch_all(
                        url=table_config['table_endpoint'],
                        filters=table_config['filter'],
                        reports=True,
                        export='df',
                    )
                    list_of_intent_dfs.append({intent_name: df})
        return list_of_intent_dfs

    def fetch_other_check_data(self):
        for get_intent_conf in self.toml_data['intent_checks']:
            for intent_name, table_config in get_intent_conf.items():
                if isinstance(table_config, bool):
                    if intent_name == 'cve':
                        vuln = Vulnerabilities(self.ipf, nvd_api_key=self.nist_api_key)
                        vulns = vuln.check_versions()
                    if intent_name == 'backups':
                        device_config = DeviceConfigs(client=self.ipf)
                        device_configs = device_config.get_all_configurations()
        return vulns, device_configs

    def fetch_app_data(self, for_streamlit=False):
        return_data = list()
        for idx, application_config in enumerate(self.toml_data['applications'], start=1):
            app_unicast_lookup = Unicast(
                startingPoint=application_config['source'],
                destinationPoint=application_config['destination'],
                dstPorts=application_config['port'],
                protocol=application_config['protocol'],
            )
            app_graph_png = self.ipf.diagram.png(app_unicast_lookup)
            app_name = application_config['name']
            if not for_streamlit:
                with open(f'outputs/{app_name}.png', 'wb') as f:
                    f.write(app_graph_png)
            else:
                st.write(f"# Application Data {idx}")
                st.image(app_graph_png)
            app_graph_json = self.ipf.diagram.json(app_unicast_lookup)
            app_graph_nodes = app_graph_json['graphResult']['graphData']['nodes']
            device_sn_to_fetch = [
                node_value['sn'] for node_value in app_graph_nodes.values()
                if node_value['type'] in ['l3switch', 'fw', 'switch', 'router', 'lb']
                ]
            filters = {"or": [{"sn": ["like", sn]} for sn in device_sn_to_fetch]}
            device_inventory_df = self.ipf.fetch_all(
                url='inventory/devices',
                filters=filters,
                reports=True,
                export='df',
                columns=self.ipf_columns_to_fetch
            )
            return_data.append((device_inventory_df, app_graph_png))
        return return_data

    def build_report(self, all_intent_violations_list_df, vuls, device_backup, list_app_tuple, for_streamlit=False):
        final_report_df = list()
        all_devices = self.ipf.fetch_all(url='inventory/devices', export='df', columns=self.ipf_columns_to_fetch)
        # process intent checks
        all_merged_df = list()
        for intent_response in all_intent_violations_list_df:
            for intent_name, intent_df in intent_response.items():
                if intent_name == 'unmanged_neighbors' or intent_df.empty:
                    merged_df = None
                    all_merged_df.append({intent_name: merged_df})
                    all_devices[intent_name] = False
                    continue
                all_devices[intent_name] = False
                merged_df = pd.merge(all_devices, intent_df[['sn']], on='sn')
                all_merged_df.append({intent_name: merged_df})
                all_devices.loc[all_devices['sn'].isin(merged_df['sn']), intent_name] = True

        # process app data
        for app_tuple in list_app_tuple:
            app_df, app_png = app_tuple
            for merged_df_dict in all_merged_df:
                for intent_name, intent_df in merged_df_dict.items():
                    if intent_df is None:
                        app_df[intent_name] = False
                        continue
                    app_df[intent_name] = False
                    merged_df = pd.merge(app_df, intent_df[['sn']], on='sn')
                    app_df.loc[app_df['sn'].isin(merged_df['sn']), intent_name] = True
            final_report_df.append(app_df)

        # process cves
        cve_dataframes = list()
        all_devices['cve'] = False
        for vul in vuls:
            cve_totals_df = pd.DataFrame().from_dict(vul.dict()).loc['total_results']
            cve_dataframes.append(cve_totals_df)
        for cve_dataframe in cve_dataframes:
            all_devices.loc[all_devices['version'].isin([cve_dataframe['version']]), 'cve'] = cve_dataframe['cves']
            for df in final_report_df:
                df.loc[df['version'].isin([cve_dataframe['version']]), 'cve'] = cve_dataframe['cves']

        # process device backup
        all_devices['backups'] = False
        flattened_configs = [config for configs in device_backup.values() for config in configs]
        backup_configs_df = pd.DataFrame([config.dict() for config in flattened_configs])
        all_devices['backups'] = all_devices['sn'].isin(backup_configs_df['sn'])
        for df in final_report_df:
            df['backups'] = df['sn'].isin(backup_configs_df['sn'])
        for idx, df in enumerate(final_report_df):
            if for_streamlit:
                for idx, report in enumerate(final_report_df, start= 1):
                    st.write(f"# App Data {idx}")
                    st.dataframe(report[idx])
                    st.write()
                st.write("# All Devices")
                st.write(all_devices)
                return all_devices, final_report_df
            else:
                all_devices.to_csv('outputs/all_devices.csv')
                df.to_csv(f'outputs/{idx}.csv')
        return all_devices, final_report_df


def main():
    fetch_data = FetchDataForReporting()
    all_intent_violations_list_df = fetch_data.fetch_intent_checks_data()
    vuls, device_backup = fetch_data.fetch_other_check_data()
    list_app_tuple = fetch_data.fetch_app_data()
    return fetch_data.build_report(all_intent_violations_list_df, vuls, device_backup, list_app_tuple)


