from time import time
from typing import Dict, Sized

from flask import redirect, render_template, request, url_for
from flask_security import login_required

from helperFunctions.database import ConnectTo
from helperFunctions.web_interface import format_time
from statistic.update import StatisticUpdater
from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_compare import CompareDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_frontend_editing import FrontendEditingDbInterface
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class MiscellaneousRoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule('/', 'home', self._app_home)
        self._app.add_url_rule('/about', 'about', self._app_about)
        self._app.add_url_rule('/comment/<uid>', 'comment/<uid>', self._app_add_comment, methods=['GET', 'POST'])
        self._app.add_url_rule('/admin/delete_comment/<uid>/<timestamp>', '/admin/delete_comment/<uid>/<timestamp>', self._app_delete_comment)
        self._app.add_url_rule('/admin/delete/<uid>', '/admin/delete/<uid>', self._app_delete_firmware)
        self._app.add_url_rule('/admin/missing_analyses', 'admin/missing_analyses', self._app_find_missing_analyses, methods=['GET'])

    @login_required
    @roles_accepted(*PRIVILEGES['status'])
    def _app_home(self):
        stats = StatisticUpdater(config=self._config)
        with ConnectTo(FrontEndDbInterface, config=self._config) as sc:
            latest_firmware_submissions = sc.get_last_added_firmwares(int(self._config['database'].get('number_of_latest_firmwares_to_display', '10')))
            latest_comments = sc.get_latest_comments(int(self._config['database'].get('number_of_latest_firmwares_to_display', '10')))
        with ConnectTo(CompareDbInterface, config=self._config) as sc:
            latest_comparison_results = sc.page_compare_results(limit=10)
        general_stats = stats.get_general_stats()
        stats.shutdown()
        return render_template('home.html', general_stats=general_stats, latest_firmware_submissions=latest_firmware_submissions,
                               latest_comments=latest_comments, latest_comparison_results=latest_comparison_results)

    @staticmethod
    def _app_about():
        return render_template('about.html')

    @roles_accepted(*PRIVILEGES['comment'])
    def _app_add_comment(self, uid):
        error = False
        if request.method == 'POST':
            comment = request.form['comment']
            author = request.form['author']
            with ConnectTo(FrontendEditingDbInterface, config=self._config) as sc:
                sc.add_comment_to_object(uid, comment, author, round(time()))
            return redirect(url_for('analysis/<uid>', uid=uid))
        with ConnectTo(FrontEndDbInterface, config=self._config) as sc:
            if not sc.existence_quick_check(uid):
                error = True
        return render_template('add_comment.html', uid=uid, error=error)

    @roles_accepted(*PRIVILEGES['delete'])
    def _app_delete_comment(self, uid, timestamp):
        with ConnectTo(FrontendEditingDbInterface, config=self._config) as sc:
            sc.delete_comment(uid, timestamp)
        return redirect(url_for('analysis/<uid>', uid=uid))

    @roles_accepted(*PRIVILEGES['delete'])
    def _app_delete_firmware(self, uid):
        with ConnectTo(FrontEndDbInterface, config=self._config) as sc:
            is_firmware = sc.is_firmware(uid)
        if not is_firmware:
            return render_template('error.html', message='Firmware not found in database: {}'.format(uid))
        with ConnectTo(AdminDbInterface, config=self._config) as sc:
            deleted_virtual_path_entries, deleted_files = sc.delete_firmware(uid)
        return render_template('delete_firmware.html', deleted_vps=deleted_virtual_path_entries, deleted_files=deleted_files, uid=uid)

    @roles_accepted(*PRIVILEGES['delete'])
    def _app_find_missing_analyses(self):
        template_data = {
            'missing_files': self._find_missing_files(),
            'missing_analyses': self._find_missing_analyses()
        }
        return render_template('find_missing_analyses.html', **template_data)

    def _find_missing_files(self):
        start = time()
        with ConnectTo(FrontEndDbInterface, config=self._config) as db:
            parent_to_included = db.find_missing_files()
        return {
            'tuples': list(parent_to_included.items()),
            'count': self._count_values(parent_to_included),
            'duration': format_time(time() - start),
        }

    def _find_missing_analyses(self):
        start = time()
        with ConnectTo(FrontEndDbInterface, config=self._config) as db:
            missing_analyses = db.find_missing_analyses()
        return {
            'tuples': list(missing_analyses.items()),
            'count': self._count_values(missing_analyses),
            'duration': format_time(time() - start),
        }

    @staticmethod
    def _count_values(dictionary: Dict[str, Sized]) -> int:
        return sum(len(e) for e in dictionary.values())
