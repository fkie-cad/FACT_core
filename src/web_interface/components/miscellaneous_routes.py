from pathlib import Path
from time import time
from typing import Dict, Sized

from flask import redirect, render_template, request, url_for
from flask_security import login_required

from helperFunctions.database import ConnectTo
from helperFunctions.program_setup import get_log_file_for_component
from helperFunctions.web_interface import format_time
from intercom.front_end_binding import InterComFrontEndBinding
from statistic.update import StatsUpdater
from storage_postgresql.db_interface_admin import AdminDbInterface
from storage_postgresql.db_interface_comparison import ComparisonDbInterface
from storage_postgresql.db_interface_frontend import FrontEndDbInterface
from storage_postgresql.db_interface_frontend_editing import FrontendEditingDbInterface
from web_interface.components.component_base import GET, POST, AppRoute, ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class MiscellaneousRoutes(ComponentBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = FrontEndDbInterface(config=self._config)
        self.comparison_dbi = ComparisonDbInterface(config=self._config)
        self.admin_dbi = AdminDbInterface(config=self._config)
        self.editing_dbi = FrontendEditingDbInterface(config=self._config)

    @login_required
    @roles_accepted(*PRIVILEGES['status'])
    @AppRoute('/', GET)
    def show_home(self):
        stats = StatsUpdater(config=self._config)
        latest_count = int(self._config['database'].get('number_of_latest_firmwares_to_display', '10'))
        latest_firmware_submissions = self.db.get_last_added_firmwares(latest_count)
        latest_comments = self.db.get_latest_comments(latest_count)
        latest_comparison_results = self.comparison_dbi.page_comparison_results(limit=10)
        ajax_stats_reload_time = int(self._config['database']['ajax_stats_reload_time'])
        general_stats = stats.get_general_stats()
        return render_template(
            'home.html',
            general_stats=general_stats,
            latest_firmware_submissions=latest_firmware_submissions,
            latest_comments=latest_comments,
            latest_comparison_results=latest_comparison_results,
            ajax_stats_reload_time=ajax_stats_reload_time
        )

    @AppRoute('/about', GET)
    def show_about(self):  # pylint: disable=no-self-use
        return render_template('about.html')

    @roles_accepted(*PRIVILEGES['comment'])
    @AppRoute('/comment/<uid>', POST)
    def post_comment(self, uid):
        comment = request.form['comment']
        author = request.form['author']
        self.editing_dbi.add_comment_to_object(uid, comment, author, round(time()))
        return redirect(url_for('show_analysis', uid=uid))

    @roles_accepted(*PRIVILEGES['comment'])
    @AppRoute('/comment/<uid>', GET)
    def show_add_comment(self, uid):
        error = not self.db.exists(uid)
        return render_template('add_comment.html', uid=uid, error=error)

    @roles_accepted(*PRIVILEGES['delete'])
    @AppRoute('/admin/delete_comment/<uid>/<timestamp>', GET)
    def delete_comment(self, uid, timestamp):
        self.editing_dbi.delete_comment(uid, timestamp)
        return redirect(url_for('show_analysis', uid=uid))

    @roles_accepted(*PRIVILEGES['delete'])
    @AppRoute('/admin/delete/<uid>', GET)
    def delete_firmware(self, uid):
        if not self.db.is_firmware(uid):
            return render_template('error.html', message=f'Firmware not found in database: {uid}')
        deleted_virtual_path_entries, deleted_files = self.admin_dbi.delete_firmware(uid)
        return render_template(
            'delete_firmware.html',
            deleted_vps=deleted_virtual_path_entries,
            deleted_files=deleted_files,
            uid=uid
        )

    @roles_accepted(*PRIVILEGES['delete'])
    @AppRoute('/admin/missing_analyses', GET)
    def find_missing_analyses(self):
        template_data = {
            'missing_files': self._find_missing_files(),
            'orphaned_files': self._find_orphaned_files(),
            'missing_analyses': self._find_missing_analyses(),
            'failed_analyses': self._find_failed_analyses(),
        }
        return render_template('find_missing_analyses.html', **template_data)

    def _find_missing_files(self):  # FixMe: should be always empty with postgres
        start = time()
        parent_to_included = self.db.find_missing_files()
        return {
            'tuples': list(parent_to_included.items()),
            'count': self._count_values(parent_to_included),
            'duration': format_time(time() - start),
        }

    def _find_orphaned_files(self):  # FixMe: should be always empty with postgres
        start = time()
        parent_to_included = self.db.find_orphaned_objects()
        return {
            'tuples': list(parent_to_included.items()),
            'count': self._count_values(parent_to_included),
            'duration': format_time(time() - start),
        }

    def _find_missing_analyses(self):
        start = time()
        missing_analyses = self.db.find_missing_analyses()
        return {
            'tuples': list(missing_analyses.items()),
            'count': self._count_values(missing_analyses),
            'duration': format_time(time() - start),
        }

    @staticmethod
    def _count_values(dictionary: Dict[str, Sized]) -> int:
        return sum(len(e) for e in dictionary.values())

    def _find_failed_analyses(self):
        start = time()
        failed_analyses = self.db.find_failed_analyses()
        return {
            'tuples': list(failed_analyses.items()),
            'count': self._count_values(failed_analyses),
            'duration': format_time(time() - start),
        }

    @roles_accepted(*PRIVILEGES['view_logs'])
    @AppRoute('/admin/logs', GET)
    def show_logs(self):
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            backend_logs = '\n'.join(sc.get_backend_logs())
        frontend_logs = '\n'.join(self._get_frontend_logs())
        return render_template('logs.html', backend_logs=backend_logs, frontend_logs=frontend_logs)

    def _get_frontend_logs(self):
        frontend_logs = Path(get_log_file_for_component('frontend', self._config))
        if frontend_logs.is_file():
            return frontend_logs.read_text().splitlines()[-100:]
        return []
