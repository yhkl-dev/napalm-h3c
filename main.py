from pprint import pprint

from napalm_h3c_comware.comware import ComwareDriver

with ComwareDriver(
    "172.31.19.250",
    "bkadmin",
    "Admin#1234",
    timeout=200,
    optional_args={"read_output_override": 300, "fast_cli": False, "conn_timeout": 150, "global_delay_factor": 30},
) as driver:
    # driver.open()
    pprint(driver.get_lldp_neighbors())
