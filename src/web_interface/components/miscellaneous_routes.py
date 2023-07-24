from __future__ import annotations

from pathlib import Path
from time import time

from flask import redirect, render_template, request, url_for
from flask_security import login_required

import config
from helperFunctions.database import ConnectTo, get_shared_session
from helperFunctions.web_interface import format_time
from statistic.update import StatsUpdater
from web_interface.components.component_base import GET, POST, AppRoute, ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sized


class MiscellaneousRoutes(ComponentBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stats_updater = StatsUpdater(stats_db=self.db.stats_updater)

    @login_required
    @roles_accepted(*PRIVILEGES['status'])
    @AppRoute('/', GET)
    def show_home(self):
        latest_count = config.frontend.number_of_latest_firmwares_to_display
        with get_shared_session(self.db.frontend) as frontend_db:
            latest_firmware_submissions = frontend_db.get_last_added_firmwares(latest_count)
            latest_comments = frontend_db.get_latest_comments(latest_count)
        latest_comparison_results = self.db.comparison.page_comparison_results(limit=10)
        ajax_stats_reload_time = config.frontend.ajax_stats_reload_time
        general_stats = self.stats_updater.get_general_stats()

        return render_template(
            'home.html',
            general_stats=general_stats,
            latest_firmware_submissions=latest_firmware_submissions,
            latest_comments=latest_comments,
            latest_comparison_results=latest_comparison_results,
            ajax_stats_reload_time=ajax_stats_reload_time,
        )

    @AppRoute('/about', GET)
    def show_about(self):
        return render_template('about.html')

    @roles_accepted(*PRIVILEGES['comment'])
    @AppRoute('/comment/<uid>', POST)
    def post_comment(self, uid):
        comment = request.form['comment']
        author = request.form['author']
        self.db.editing.add_comment_to_object(uid, comment, author, round(time()))
        return redirect(url_for('show_analysis', uid=uid))

    @roles_accepted(*PRIVILEGES['comment'])
    @AppRoute('/comment/<uid>', GET)
    def show_add_comment(self, uid):
        error = not self.db.frontend.exists(uid)
        return render_template('add_comment.html', uid=uid, error=error)

    @roles_accepted(*PRIVILEGES['delete'])
    @AppRoute('/admin/delete_comment/<uid>/<timestamp>', GET)
    def delete_comment(self, uid, timestamp):
        self.db.editing.delete_comment(uid, timestamp)
        return redirect(url_for('show_analysis', uid=uid))

    @roles_accepted(*PRIVILEGES['delete'])
    @AppRoute('/admin/delete/<uid>', GET)
    def delete_firmware(self, uid):
        if not self.db.frontend.is_firmware(uid):
            return render_template('error.html', message=f'Firmware not found in database: {uid}')
        deleted_virtual_path_entries, deleted_files = self.db.admin.delete_firmware(uid)
        return render_template(
            'delete_firmware.html', deleted_vps=deleted_virtual_path_entries, deleted_files=deleted_files, uid=uid
        )

    @roles_accepted(*PRIVILEGES['delete'])
    @AppRoute('/admin/missing_analyses', GET)
    def find_missing_analyses(self):
        template_data = {
            'missing_analyses': self._find_missing_analyses(),
            'failed_analyses': self._find_failed_analyses(),
        }
        return render_template('find_missing_analyses.html', **template_data)

    def _find_missing_analyses(self):
        start = time()
        missing_analyses = self.db.frontend.find_missing_analyses()
        return {
            'tuples': list(missing_analyses.items()),
            'count': self._count_values(missing_analyses),
            'duration': format_time(time() - start),
        }

    @staticmethod
    def _count_values(dictionary: dict[str, Sized]) -> int:
        return sum(len(e) for e in dictionary.values())

    def _find_failed_analyses(self):
        start = time()
        failed_analyses = self.db.frontend.find_failed_analyses()
        return {
            'tuples': list(failed_analyses.items()),
            'count': self._count_values(failed_analyses),
            'duration': format_time(time() - start),
        }

    @roles_accepted(*PRIVILEGES['view_logs'])
    @AppRoute('/admin/logs', GET)
    def show_logs(self):
        with ConnectTo(self.intercom) as sc:
            backend_logs = '\n'.join(sc.get_backend_logs())
        frontend_logs = '\n'.join(self._get_frontend_logs())
        return render_template('logs.html', backend_logs=backend_logs, frontend_logs=frontend_logs)

    def _get_frontend_logs(self):
        frontend_logs = Path(config.frontend.logging.file_frontend)
        if frontend_logs.is_file():
            return frontend_logs.read_text().splitlines()[-100:]
        return []
