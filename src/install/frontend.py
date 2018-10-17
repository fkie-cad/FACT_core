import logging
import os
import shutil
from pathlib import Path

from common_helper_process import execute_shell_command_get_return_code

from helperFunctions.config import load_config
from helperFunctions.install import OperateInDirectory, pip_install_packages, InstallationError, check_if_command_in_path


def wget_static_web_content(url, target_folder, additional_actions, resource_logging_name=None):
    logging.info('Install static {} content'.format(resource_logging_name if resource_logging_name else url))
    with OperateInDirectory(target_folder):
        execute_shell_command_get_return_code('wget -nc {}'.format(url))
        for action in additional_actions:
            execute_shell_command_get_return_code(action)


def _patch_bootstrap():
    with OperateInDirectory('bootstrap/css'):
        for file_name in ['bootstrap.min.css', 'bootstrap.min.css.map', 'bootstrap-theme.min.css',
                          'bootstrap-theme.min.css.map', 'bootstrap.css.map', 'bootstrap-theme.css.map']:
            Path(file_name).unlink()
            execute_shell_command_get_return_code(
                'patch --forward -r - bootstrap.css ../../../../bootstrap/patches/bootstrap.patch')
            execute_shell_command_get_return_code(
                'patch --forward -r - bootstrap-theme.css ../../../../bootstrap/patches/bootstrap-theme.patch')


def _create_directory_for_authentication():
    logging.info('Creating directory for authentication')

    config = load_config('main.cfg')
    dburi = config.get('data_storage', 'user_database')
    factauthdir = '/'.join(dburi.split('/')[:-1])[10:]

    user_id = os.getuid()
    group_id = os.getgid()

    mkdir_output, mkdir_code = execute_shell_command_get_return_code('sudo mkdir -p --mode=0744 {}'.format(factauthdir))
    chown_output, chown_code = execute_shell_command_get_return_code('sudo chown {}:{} {}'.format(user_id, group_id, factauthdir))

    if not all(return_code == 0 for return_code in [mkdir_code, chown_code]):
        raise InstallationError('Error in creating directory for authentication database.\n{}'.format('\n'.join((mkdir_output, chown_output))))


def main(distribution, radare, nginx):
    pip_install_packages('flask', 'flask_restful', 'flask_security', 'flask_sqlalchemy', 'flask-paginate', 'Flask-API', 'uwsgi', 'bcrypt')

    # installing web/js-frameworks    #
    with OperateInDirectory('../web_interface/static'):
        wget_static_web_content('https://github.com/twbs/bootstrap/releases/download/v3.3.7/bootstrap-3.3.7-dist.zip', '.', ['unzip -o bootstrap-3.3.7-dist.zip', 'rm bootstrap-3.3.7-dist.zip', 'rm -rf bootstrap', 'mv bootstrap-3.3.7-dist bootstrap'], 'bootstrap')

        _patch_bootstrap()

        wget_static_web_content('https://ajax.googleapis.com/ajax/libs/jquery/1.12.0/jquery.min.js', 'bootstrap/js', [], 'jquery')
        wget_static_web_content('https://raw.githubusercontent.com/Eonasdan/bootstrap-datetimepicker/master/build/js/bootstrap-datetimepicker.min.js', 'bootstrap/js', [], 'datetimepicker js')
        wget_static_web_content('https://raw.githubusercontent.com/Eonasdan/bootstrap-datetimepicker/master/build/css/bootstrap-datetimepicker.min.css', 'bootstrap/css', [], 'datetimepicker css')
        wget_static_web_content('wget -nc https://raw.githubusercontent.com/moment/moment/develop/moment.js', 'bootstrap/js', [], 'moment.js')

        if not Path('bootstrap3-editable').exists():
            wget_static_web_content('https://vitalets.github.io/x-editable/assets/zip/bootstrap3-editable-1.5.1.zip', '.', ['unzip -o bootstrap3-editable-1.5.1.zip', 'rm bootstrap3-editable-1.5.1.zip CHANGELOG.txt LICENSE-MIT README.md', 'rm -rf inputs-ext'], 'x-editable')

        if Path('jstree').is_dir():
            shutil.rmtree('jstree')
        wget_static_web_content('https://github.com/vakata/jstree/zipball/3.3.2', '.', ['unzip 3.3.2', 'rm 3.3.2', 'mv vakata* jstree'], 'jstree')

        wget_static_web_content('https://ajax.googleapis.com/ajax/libs/angularjs/1.4.8/angular.min.js', '.', [], 'angularJS')
        wget_static_web_content('https://github.com/chartjs/Chart.js/releases/download/v2.3.0/Chart.js', '.', [], 'charts.js')

    # create user database
    _create_directory_for_authentication()

    if nginx:
        '''
        echo "####################################"
        echo "# installing and configuring nginx #"
        echo "####################################"
        sudo apt-get install -y nginx
        echo "generating a new certificate..."
        openssl genrsa -out fact.key 4096
        openssl req -new -key fact.key -out fact.csr
        openssl x509 -req -days 730 -in fact.csr -signkey fact.key -out fact.crt
        sudo mv fact.key fact.csr fact.crt /etc/nginx
        sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
        sudo rm /etc/nginx/nginx.conf
        (cd ../config && sudo ln -s $PWD/nginx.conf /etc/nginx/nginx.conf)
        sudo mkdir /etc/nginx/error
        (cd ../web_interface/templates/ && sudo ln -s $PWD/maintenance.html /etc/nginx/error/maintenance.html)
        sudo nginx -s reload
        '''
        pass

    if radare:
        if check_if_command_in_path('docker-compose'):
            logging.info('Initiializing docker container for radare')
            with OperateInDirectory('radare'):
                output, return_code = execute_shell_command_get_return_code('docker-compose build')
                if return_code != 0:
                    raise InstallationError('Failed to initialize radare container:\n{}'.format(output))
        else:
            raise InstallationError('docker-compose is not installed. Please (re-)run pre_install.sh')

    # cd ../../
    # rm start_fact_frontend
    # ln -s src/start_fact_frontend.py start_fact_frontend

    return 0
