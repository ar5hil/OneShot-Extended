import re
import csv
import codecs
import subprocess

from rich.table import Table
from rich.console import Console

from src import logger
from src.utils import REPORTS_DIR

import src.args
import src.utils

args = src.args.parseArgs()
_console = Console()

class WiFiScanner:
    """Handles scanning, parsing, and displaying networks."""

    def __init__(self, interface: str, vuln_list: str = None):
        self.INTERFACE = interface
        self.VULN_LIST = vuln_list

        reports_fname = REPORTS_DIR + 'stored.csv'

        try:
            with open(reports_fname, 'r', newline='', encoding='utf-8') as file:
                csv_reader = csv.reader(file,
                    delimiter=';', quoting=csv.QUOTE_ALL
                )
                next(csv_reader)
                self.STORED = []
                for row in csv_reader:
                    self.STORED.append(
                        (
                            row[1],
                            row[2]
                        )
                    )
        except FileNotFoundError:
            self.STORED = []

    def displayNetworks(self, networks: dict[int, dict]) -> None:
        """Display networks in a rich formatted table."""
        network_list_items = list(networks.items())

        if not network_list_items:
            return

        if args.reverse_scan:
            network_list_items = network_list_items[::-1]

        def truncateStr(s, length, postfix='…'):
            if len(s) > length:
                k = length - len(postfix)
                s = s[:k] + postfix
            return s

        _console.print(
            '[green]Vulnerable model[/green] | '
            '[green]Vulnerable WPS ver.[/green] | '
            '[red]WPS locked[/red] | '
            '[yellow]Already stored[/yellow]'
        )

        table = Table(show_header=True, header_style='bold cyan', box=None, padding=(0, 1))

        table.add_column('#', style='dim', width=4)
        table.add_column('BSSID', width=18)
        table.add_column('ESSID', width=27)
        table.add_column('Sec.', width=10)
        table.add_column('PWR', width=4)
        table.add_column('Ver.', width=4)
        table.add_column('WSC name', width=27)
        table.add_column('WSC model', width=27)

        for n, network in network_list_items:
            model = f'{network["Model"]} {network["Model number"]}'.strip()
            essid = truncateStr(network['ESSID'], 25)
            device_name = truncateStr(network['Device name'], 27)
            number = f'{n})'

            row_style = ''
            if (network['BSSID'], network['ESSID']) in self.STORED:
                row_style = 'yellow'
            elif network['WPS version'] == '1.0':
                row_style = 'green'
            elif network['WPS locked']:
                row_style = 'red'
            elif self.VULN_LIST and (model in self.VULN_LIST or device_name in self.VULN_LIST):
                row_style = 'green'

            table.add_row(
                number, network['BSSID'], essid,
                network['Security type'], str(network['Level']),
                network['WPS version'], device_name, model,
                style=row_style if row_style else None
            )

        _console.print()
        _console.print(table)
        _console.print()

    def promptNetwork(self) -> tuple[str, dict] | None:
        """Prompts the user to select a network from the available WPS networks."""

        networks = self._scan()

        if not networks:
            logger.error('No WPS networks found.')
            return

        self.displayNetworks(networks)

        while True:
            try:
                network_no = input('Select target (press Enter to refresh): ')

                if network_no.lower() in {'r', '0', ''}:
                    if args.clear:
                        src.utils.clearScreen()
                    result = self.promptNetwork()
                    if result is None:
                        continue
                    return result

                if int(network_no) in networks.keys():
                    selected_network = networks[int(network_no)]
                    return (selected_network['BSSID'], selected_network)

                raise IndexError
            except (IndexError, ValueError):
                logger.warning('Invalid number')

    def getNetworks(self) -> dict[int, dict] | None:
        """Return all scanned WPS-enabled networks without prompting."""
        networks = self._scan()
        if not networks:
            return None
        return networks

    def _scan(self) -> dict[int, dict] | bool:
        """Parsing iw scan results."""

        def handleNetwork(_line, result, networks):
            networks.append(
                {
                    'ESSID': '',
                    'Security type': 'Unknown',
                    'WPS': False,
                    'WPS version': '1.0',
                    'WPS locked': False,
                    'Model': '',
                    'Model number': '',
                    'Device name': ''
                }
            )
            networks[-1]['BSSID'] = result.group(1).upper()

        def handleEssid(_line, result, networks):
            try:
                d = result.group(1)
                essid = networks[-1]['ESSID'] = codecs.decode(d,'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
                networks[-1]['ESSID'] = essid if essid.strip('\x00 ') else '<hidden>'
            except (AttributeError, IndexError):
                networks[-1]['ESSID'] = '<hidden>'

        def handleLevel(_line, result, networks):
            networks[-1]['Level'] = int(float(result.group(1)))

        def handleSecurityType(_line, result, networks):
            sec = networks[-1]['Security type']
            if result.group(1) == 'capability':
                if 'Privacy' in result.group(2):
                    sec = 'WEP'
                else:
                    sec = 'Open'
            elif sec == 'WEP':
                if result.group(1) == 'RSN':
                    sec = 'WPA2'
                elif result.group(1) == 'WPA':
                    sec = 'WPA'
            elif sec == 'WPA':
                if result.group(1) == 'RSN':
                    sec = 'WPA/WPA2'
            elif sec == 'WPA2':
                if result.group(1) == 'PSK SAE':
                    sec = 'WPA2/WPA3'
                elif result.group(1) == 'WPA':
                    sec = 'WPA/WPA2'
            networks[-1]['Security type'] = sec

        def handleWps(_line, result, networks):
            networks[-1]['WPS'] = True

        def handleWpsVersion(_line, result, networks):
            wps_ver = networks[-1]['WPS version']
            wps_ver_filtered = result.group(1).replace('* Version2:', '')
            if wps_ver_filtered == '2.0':
                wps_ver = '2.0'
            networks[-1]['WPS version'] = wps_ver

        def handleWpsLocked(_line, result, networks):
            flag = int(result.group(1), 16)
            if flag:
                networks[-1]['WPS locked'] = True

        def handleModel(_line, result, networks):
            d = result.group(1)
            networks[-1]['Model'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handleModelNumber(_line, result, networks):
            d = result.group(1)
            networks[-1]['Model number'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        def handleDeviceName(_line, result, networks):
            d = result.group(1)
            networks[-1]['Device name'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')

        networks = []
        matchers = {
            re.compile(r'BSS (\S+)( )?\(on \w+\)'): handleNetwork,
            re.compile(r'SSID: (.*)'): handleEssid,
            re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'): handleLevel,
            re.compile(r'(capability): (.+)'): handleSecurityType,
            re.compile(r'(RSN):\t [*] Version: (\d+)'): handleSecurityType,
            re.compile(r'(WPA):\t [*] Version: (\d+)'): handleSecurityType,
            re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)'): handleWps,
            re.compile(r' [*] Version2: (.+)'): handleWpsVersion,
            re.compile(r' [*] Authentication suites: (.+)'): handleSecurityType,
            re.compile(r' [*] AP setup locked: (0x[0-9]+)'): handleWpsLocked,
            re.compile(r' [*] Model: (.*)'): handleModel,
            re.compile(r' [*] Model Number: (.*)'): handleModelNumber,
            re.compile(r' [*] Device name: (.*)'): handleDeviceName
        }

        command = ['iw', 'dev', f'{self.INTERFACE}', 'scan']
        try:
            iw_scan_process = subprocess.run(command,
                encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
        except (subprocess.CalledProcessError, FileNotFoundError) as error:
            logger.error(f'Failed to perform an iw scan: \n {error}')
            return

        lines = iw_scan_process.stdout.splitlines()

        if args.verbose:
            print('\n'.join(lines))

        for line in lines:
            if line.startswith('command failed:'):
                logger.error(f'Error: {line}')
                return False

            line = line.strip('\t')

            for regexp, handler in matchers.items():
                res = re.match(regexp, line)
                if res:
                    handler(line, res, networks)

        networks = list(filter(lambda x: bool(x['WPS']), networks))

        if not networks:
            return False

        networks.sort(key=lambda x: x['Level'], reverse=True)

        network_list = {(i + 1): network for i, network in enumerate(networks)}
        return network_list
