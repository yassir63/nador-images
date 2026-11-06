#----------------------------------------------------------------------------
# Author: Niloy Saha
# Email: niloysaha.ns@gmail.com
# version ='1.0.0'
# ---------------------------------------------------------------------------
"""
Prometheus exporter which exports RAN KPI.
For use with the 5G-MONARCH project and OAI.
"""
import os
import logging
import time
import requests
import prometheus_client as prom
import argparse

from dotenv import load_dotenv

load_dotenv()
MONARCH_THANOS_URL = os.getenv("MONARCH_THANOS_URL")
DEFAULT_UPDATE_PERIOD = 1
UPDATE_PERIOD = int(os.environ.get('UPDATE_PERIOD', DEFAULT_UPDATE_PERIOD))
EXPORTER_PORT = 9000


# Prometheus variables
NUMBER_UES = prom.Gauge('number_ues', 'Number of connected UEs in the gNB')
SATURATION_PERCENTAGE = prom.Gauge('saturation_percentage', 'Percentage of total gNB PRBs currently scheduled (NPRB sum / total PRBs * 100)', ['rnti'])
# SATURATION_PERCENTAGE = prom.Gauge('saturation_percentage', 'Percentage of total gNB PRBs currently scheduled (NPRB sum / total PRBs * 100)')

# get rid of bloat
prom.REGISTRY.unregister(prom.PROCESS_COLLECTOR)
prom.REGISTRY.unregister(prom.PLATFORM_COLLECTOR)
prom.REGISTRY.unregister(prom.GC_COLLECTOR)

def query_prometheus(params, url):
    """
    Query Prometheus using requests and return value.
    params: The parameters for the Prometheus query.
    url: The URL of the Prometheus server.
    Returns: The result of the Prometheus query.
    """
    try:
        r = requests.get(url + '/api/v1/query', params)
        data = r.json()

        results = data["data"]["result"]
        return results
        
    except requests.exceptions.RequestException as e:
        log.error(f"Failed to query Prometheus: {e}")
    except (KeyError, IndexError, ValueError) as e:
        log.error(f"Failed to parse Prometheus response: {e}")
        log.warning("No data available!")


def get_number_ues():
    rntis = set()
    metric = "oai_gnb_mac_lcid_tx_bytes"

    # Only consider LCID 4
    query = f'{metric}{{lcid="4"}}'
    results = query_prometheus({'query': query}, MONARCH_THANOS_URL)

    if not results:
        log.warning("No LCID=4 results for number_ues")
        return 0

    for result in results:
        rnti = result["metric"].get("rnti")

        # Presence of LCID=4 series = UE is "connected"
        if rnti:
            rntis.add(rnti)

    count = len(rntis)
    log.info(f"Found {count} connected UEs (LCID=4 presence)")
    return count

def get_saturation_percentage():
    """
    Compute gNB PRB saturation only for UEs with LCID=4 (connected UEs):
    (sum of mac_nprb for LCID=4 UEs) / (total PRBs from L1 stats) * 100
    """

    connected_rntis = set()
    lcid4_query = 'oai_gnb_mac_lcid_tx_bytes{lcid="4"}'
    lcid4_results = query_prometheus({"query": lcid4_query}, MONARCH_THANOS_URL)

    if lcid4_results:
        for result in lcid4_results:
            rnti = result["metric"].get("rnti")
            if rnti:
                connected_rntis.add(rnti)
    else:
        log.warning("No LCID=4 results found")

    log.info(f"Found {len(connected_rntis)} connected UEs (LCID=4)")

    mac_nprb_query = "oai_gnb_mac_nprb"
    nprb_results = query_prometheus({"query": mac_nprb_query}, MONARCH_THANOS_URL)

    total_nprb = 0.0
    if nprb_results:
        for result in nprb_results:
            try:
                rnti = result["metric"]["rnti"]
                if rnti in connected_rntis:
                    val = float(result["value"][1])
                    total_nprb += val
                    log.debug(f"NPRB for connected RNTI {rnti}: {val}")
            except (KeyError, ValueError) as e:
                log.warning(f"Failed to parse NPRB result: {e}")
    else:
        log.warning("No results for oai_gnb_mac_nprb")

    l1_result = query_prometheus({"query": "oai_gnb_l1_total_prbs"}, MONARCH_THANOS_URL)
    if not l1_result:
        log.warning("No results for oai_gnb_l1_total_prbs")
        return 0.0

    try:
        total_prbs = float(l1_result[0]["value"][1])
    except (IndexError, KeyError, ValueError):
        log.warning("Error parsing total PRBs")
        return 0.0

    if total_prbs == 0:
        log.warning("Total PRBs is zero")
        return 0.0

    saturation_percentage = (total_nprb / total_prbs) * 100

    log.info(
        f"Computed Saturation = {saturation_percentage:.2f}% "
        f"(Connected NPRBs={total_nprb}, Total PRBs={total_prbs})"
    )

    return saturation_percentage

def get_saturation_percentage_per_rnti():
    """
    Compute gNB PRB saturation only for UEs with LCID=4 (connected UEs):
    (sum of mac_nprb for LCID=4 UEs) / (total PRBs from L1 stats) * 100
    Returns a dictionary of the form {rnti: value (percentage)}
    """

    connected_rntis = set()
    lcid4_query = 'oai_gnb_mac_lcid_tx_bytes{lcid="4"}'
    lcid4_results = query_prometheus({"query": lcid4_query}, MONARCH_THANOS_URL)

    if lcid4_results:
        for result in lcid4_results:
            rnti = result["metric"].get("rnti")
            if rnti:
                connected_rntis.add(rnti)
    else:
        log.warning("No LCID=4 results found")

    log.info(f"Found {len(connected_rntis)} connected UEs (LCID=4)")

    l1_result = query_prometheus({"query": "oai_gnb_l1_total_prbs"}, MONARCH_THANOS_URL)
    if not l1_result:
        log.warning("No results for oai_gnb_l1_total_prbs")
        return

    try:
        total_prbs = float(l1_result[0]["value"][1])
        log.debug(f"Total PRBs from L1: {total_prbs}")
    except (IndexError, KeyError, ValueError) as e:
        log.warning(f"Error parsing total PRBs: {e}")
        return

    if total_prbs == 0:
        log.warning("Total PRBs is zero, cannot divide!")
        return

    mac_nprb_query = "oai_gnb_mac_nprb"
    nprb_results = query_prometheus({"query": mac_nprb_query}, MONARCH_THANOS_URL)

    nprbs = {}
    if nprb_results:
        for result in nprb_results:
            try:
                rnti = result["metric"]["rnti"]
                if rnti in connected_rntis:
                    val = float(result["value"][1])
                    nprbs[rnti] = val
                    log.debug(f"NPRB for connected RNTI {rnti}: {val}")
                else:
                    val = float(0)
                    nprbs[rnti] = val
                    log.debug(f"0 NPRB For Disconnected RNTI {rnti}")
            except (KeyError, ValueError) as e:
                log.warning(f"Failed to parse NPRB result: {e}")
    else:
        log.warning("No results for oai_gnb_mac_nprb")

    saturation_percentage_per_rnti = {}
    for rnti, nprb in nprbs.items():
        saturation_percentage_per_rnti[rnti] = (nprb / total_prbs) * 100
        log.info(f"Computed Saturation = {saturation_percentage_per_rnti[rnti]:.2f}%")

    return saturation_percentage_per_rnti

def main():
    log.info("Starting Prometheus server on port {}".format(EXPORTER_PORT))

    if not MONARCH_THANOS_URL:
        log.error("MONARCH_THANOS_URL is not set")
        return 

    log.info(f"Monarch Thanos URL: {MONARCH_THANOS_URL}")
    log.info(f"Update period: {UPDATE_PERIOD}")
    prom.start_http_server(EXPORTER_PORT)

    while True:
        try:
            run_kpi_computation()
        except Exception as e:
            log.error(f"Failing to run KPI computation: {e}")
        time.sleep(UPDATE_PERIOD)

def export_number_ues_to_prometheus(value):
    log.info(f"VALUE ={value}")
    NUMBER_UES.set(value)

# def export_saturation_percentage_to_prometheus(value):
#     log.info(f"VALUE ={value}")
#     SATURATION_PERCENTAGE.set(value)

def export_saturation_percentage_to_prometheus(rnti, value):
    log.info(f"RNTI={rnti} | VALUE ={value}")
    SATURATION_PERCENTAGE.labels(rnti=rnti).set(value)

def run_kpi_computation():
    # Do not retain series for UEs that are no longer present.
    SATURATION_PERCENTAGE.clear()
    number_ues = get_number_ues()
    export_number_ues_to_prometheus(number_ues)

    # saturation_percentage = get_saturation_percentage()
    # export_saturation_percentage_to_prometheus(saturation_percentage)

    saturation_percentage = get_saturation_percentage_per_rnti()
    if saturation_percentage:
        for rnti, value in saturation_percentage.items():
            export_saturation_percentage_to_prometheus(rnti, value)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='KPI calculator.')
    parser.add_argument('--log', default='info', help='Log verbosity level. Default is "info". Options are "debug", "info", "warning", "error", "critical".')

    args = parser.parse_args()

    # Convert log level from string to logging level
    log_level = getattr(logging, args.log.upper(), None)
    if not isinstance(log_level, int):
        raise ValueError(f'Invalid log level: {args.log}')
    
    # setup logger for console output
    log = logging.getLogger(__name__)
    log.setLevel(log_level)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    log.addHandler(console_handler)
        
    main()

    
    


