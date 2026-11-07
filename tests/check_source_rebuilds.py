"""Dependency-free rebuild checks; calculator mode runs inside its container."""
import importlib.util
import logging
from pathlib import Path
import sys
from unittest.mock import patch


def check_calculator():
    from importlib.metadata import version
    import prometheus_client as prom

    for line in Path('/exporter/requirements.txt').read_text().splitlines():
        name, expected = line.split('==')
        assert version(name) == expected, name
    spec = importlib.util.spec_from_file_location(
        'calculator', '/exporter/kpi_calculator.py')
    calculator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(calculator)
    calculator.log = logging.getLogger('calculator-test')
    assert calculator.EXPORTER_PORT == 9000
    assert not hasattr(calculator, 'MAC_THROUGHPUT')
    assert not hasattr(calculator, 'get_mac_throughput_per_rnti_and_direction')

    with patch.object(calculator, 'get_number_ues', return_value=2), patch.object(
        calculator, 'get_saturation_percentage_per_rnti', return_value={'42': 25.0}
    ):
        calculator.run_kpi_computation()
    samples = prom.generate_latest().decode()
    assert 'number_ues 2.0' in samples
    assert 'saturation_percentage{rnti="42"} 25.0' in samples
    assert 'mac_throughput' not in samples

    with patch.object(calculator, 'get_number_ues', return_value=0), patch.object(
        calculator, 'get_saturation_percentage_per_rnti', return_value=None
    ):
        calculator.run_kpi_computation()
    samples = prom.generate_latest().decode()
    assert 'number_ues 0.0' in samples
    assert 'rnti="42"' not in samples
    print('Calculator dependencies, exports, empty results, and stale-series checks passed')


if __name__ == '__main__':
    if sys.argv[1:] != ['calculator']:
        raise SystemExit('usage: check_source_rebuilds.py calculator')
    check_calculator()
