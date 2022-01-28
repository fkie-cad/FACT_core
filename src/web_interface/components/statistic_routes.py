from flask import render_template, request

from helperFunctions.database import ConnectTo
from helperFunctions.web_interface import apply_filters_to_query
from statistic.update import StatsUpdater
from web_interface.components.component_base import GET, AppRoute, ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class StatisticRoutes(ComponentBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stats_updater = StatsUpdater(stats_db=self.db.stats_updater)

    @roles_accepted(*PRIVILEGES['status'])
    @AppRoute('/statistic', GET)
    def show_statistics(self):
        filter_query = apply_filters_to_query(request, '{}')
        if filter_query == {}:
            stats = self._get_stats_from_db()
        else:
            stats = self._get_live_stats(filter_query)
        with self.db.frontend.get_read_only_session():
            device_classes = self.db.frontend.get_device_class_list()
            vendors = self.db.frontend.get_vendor_list()
        return render_template(
            'show_statistic.html',
            stats=stats,
            device_classes=device_classes,
            vendors=vendors,
            current_class=str(request.args.get('device_class')),
            current_vendor=str(request.args.get('vendor'))
        )

    @roles_accepted(*PRIVILEGES['status'])
    @AppRoute('/system_health', GET)
    def show_system_health(self):
        with ConnectTo(self.intercom, self._config) as sc:
            plugin_dict = sc.get_available_analysis_plugins()
        return render_template('system_health.html', analysis_plugin_info=plugin_dict)

    def _get_stats_from_db(self):
        with self.db.stats_viewer.get_read_only_session():
            stats_dict = {
                'general_stats': self.db.stats_viewer.get_statistic('general'),
                'firmware_meta_stats': self.db.stats_viewer.get_statistic('firmware_meta'),
                'file_type_stats': self.db.stats_viewer.get_statistic('file_type'),
                'malware_stats': self.db.stats_viewer.get_statistic('malware'),
                'crypto_material_stats': self.db.stats_viewer.get_statistic('crypto_material'),
                'unpacker_stats': self.db.stats_viewer.get_statistic('unpacking'),
                'ip_and_uri_stats': self.db.stats_viewer.get_statistic('ips_and_uris'),
                'architecture_stats': self.db.stats_viewer.get_statistic('architecture'),
                'release_date_stats': self.db.stats_viewer.get_statistic('release_date'),
                'exploit_mitigations_stats': self.db.stats_viewer.get_statistic('exploit_mitigations'),
                'known_vulnerabilities_stats': self.db.stats_viewer.get_statistic('known_vulnerabilities'),
                'software_stats': self.db.stats_viewer.get_statistic('software_components'),
                'elf_executable_stats': self.db.stats_viewer.get_statistic('elf_executable'),
            }
        return stats_dict

    def _get_live_stats(self, filter_query):
        self.stats_updater.set_match(filter_query)
        with self.stats_updater.db.get_read_only_session():
            stats_dict = {
                'firmware_meta_stats': self.stats_updater.get_firmware_meta_stats(),
                'file_type_stats': self.stats_updater.get_file_type_stats(),
                'malware_stats': self.stats_updater.get_malware_stats(),
                'crypto_material_stats': self.stats_updater.get_crypto_material_stats(),
                'unpacker_stats': self.stats_updater.get_unpacking_stats(),
                'ip_and_uri_stats': self.stats_updater.get_ip_stats(),
                'architecture_stats': self.stats_updater.get_architecture_stats(),
                'release_date_stats': self.stats_updater.get_time_stats(),
                'general_stats': self.stats_updater.get_general_stats(),
                'exploit_mitigations_stats': self.stats_updater.get_exploit_mitigations_stats(),
                'known_vulnerabilities_stats': self.stats_updater.get_known_vulnerabilities_stats(),
                'software_stats': self.stats_updater.get_software_components_stats(),
                'elf_executable_stats': self.stats_updater.get_executable_stats(),
            }
        return stats_dict
