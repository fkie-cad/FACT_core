# -*- coding: utf-8 -*-

from flask import render_template, request

from helperFunctions.web_interface import apply_filters_to_query, ConnectTo
from statistic.update import StatisticUpdater
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_statistic import StatisticDbViewer
from web_interface.components.component_base import ComponentBase


class StatisticRoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule("/statistic", "statistic", self._show_statistic, methods=["GET"])
        self._app.add_url_rule("/system_health", "system_health", self._show_system_health, methods=["GET"])

    def _show_statistic(self):
        filter_query = apply_filters_to_query(request, "{}")
        if filter_query == {}:
            stats = self._get_stats_from_db()
        else:
            stats = self._get_live_stats(filter_query)
        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            device_classes = connection.get_device_class_list()
            vendors = connection.get_vendor_list()
        return render_template("show_statistic.html", stats=stats, device_classes=device_classes,
                               vendors=vendors, current_class=str(request.args.get("device_class")),
                               current_vendor=str(request.args.get("vendor")))

    def _show_system_health(self):
        components = ["frontend", "database", "backend"]
        status = []
        with ConnectTo(StatisticDbViewer, self._config) as stats_db:
            for component in components:
                status.append(stats_db.get_statistic(component))
        return render_template("system_health.html", status=status)

    def _get_stats_from_db(self):
        with ConnectTo(StatisticDbViewer, self._config) as stats_db:
            stats_dict = {
                "general_stats": stats_db.get_statistic("general"),
                "firmware_meta_stats": stats_db.get_statistic("firmware_meta"),
                "file_type_stats": stats_db.get_statistic("file_type"),
                "malware_stats": stats_db.get_statistic("malware"),
                "crypto_material_stats": stats_db.get_statistic("crypto_material"),
                "unpacker_stats": stats_db.get_statistic("unpacking"),
                "ip_and_uri_stats": stats_db.get_statistic("ips_and_uris"),
                "architecture_stats": stats_db.get_statistic("architecture"),
                "release_date_stats": stats_db.get_statistic("release_date"),
                "exploit_mitigations_stats": stats_db.get_statistic("exploit_mitigations")
            }
        return stats_dict

    def _get_live_stats(self, filter_query):
        with ConnectTo(StatisticUpdater, self._config) as stats_updater:
            stats_updater.set_match(filter_query)
            stats_dict = {
                "firmware_meta_stats": stats_updater._get_firmware_meta_stats(),
                "file_type_stats": stats_updater._get_file_type_stats(),
                "malware_stats": stats_updater._get_malware_stats(),
                "crypto_material_stats": stats_updater._get_crypto_material_stats(),
                "unpacker_stats": stats_updater._get_unpacking_stats(),
                "ip_and_uri_stats": stats_updater._get_ip_stats(),
                "architecture_stats": stats_updater._get_architecture_stats(),
                "release_date_stats": stats_updater._get_time_stats(),
                "general_stats": stats_updater.get_general_stats(),
                "exploit_mitigations_stats": stats_updater._get_exploit_mitigations_stats()
            }
        return stats_dict
