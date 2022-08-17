import logging
import os
import subprocess
from contextlib import suppress
from pathlib import Path
from subprocess import PIPE, STDOUT

import requests

from helperFunctions.install import (
    InstallationError,
    OperateInDirectory,
    apt_install_packages,
    dnf_install_packages,
    install_pip_packages,
    load_main_config,
    remove_folder,
    run_cmd_with_logging
)

DEFAULT_CERT = '.\n.\n.\n.\n.\nexample.com\n.\n\n\n'
INSTALL_DIR = Path(__file__).parent
PIP_DEPENDENCIES = INSTALL_DIR / 'requirements_frontend.txt'


def execute_commands_and_raise_on_return_code(commands, error=None):  # pylint: disable=invalid-name
    for command in commands:
        bad_return = error if error else f'execute {command}'
        cmd_process = subprocess.run(command, shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
        if cmd_process.returncode != 0:
            raise InstallationError(f'Failed to {bad_return}\n{cmd_process.stdout}')


def wget_static_web_content(url, target_folder, additional_actions, resource_logging_name=None):
    logging.info(f'Install static {resource_logging_name if resource_logging_name else url} content')
    with OperateInDirectory(target_folder):
        wget_process = subprocess.run(
            f'wget -nc {url}', shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True
        )
        if wget_process.returncode != 0:
            raise InstallationError(f'Failed to fetch resource at {url}\n{wget_process.stdout}')
        for action in additional_actions:
            action_process = subprocess.run(action, shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True)
            if action_process.returncode != 0:
                raise InstallationError(f'Problem in processing resource at {url}\n{action_process.stdout}')


def _build_highlight_js():
    logging.info('Installing highlight js')

    highlight_js_url = 'https://highlightjs.org/download/'
    highlight_js_dir = 'highlight.js'
    highlight_js_zip = 'highlight.js.zip'
    if Path(highlight_js_dir).is_dir():
        remove_folder(highlight_js_dir)

    req = requests.get('https://highlightjs.org/download/')
    crsf_cookie = req.headers['Set-Cookie']
    csrf_token = crsf_cookie.split(';')[0].split('=')[1]

    commands = [
        'wget {url} --header="Host: highlightjs.org" --header="User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0" --header="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" --header="Accept-Language: en-GB,en;q=0.5" --header="Accept-Encoding: gzip, deflate, br" --header="Referer: https://highlightjs.org/download/" --header="Content-Type: application/x-www-form-urlencoded" --header="Cookie: csrftoken={token}" --header="DNT: 1" --header="Connection: keep-alive" --header="Upgrade-Insecure-Requests: 1" --post-data="apache.js=on&bash.js=on&coffeescript.js=on&cpp.js=on&cs.js=on&csrfmiddlewaretoken={token}&css.js=on&diff.js=on&http.js=on&ini.js=on&java.js=on&javascript.js=on&json.js=on&makefile.js=on&markdown.js=on&nginx.js=on&objectivec.js=on&perl.js=on&php.js=on&python.js=on&ruby.js=on&shell.js=on&sql.js=on&xml.js=on" -O {zip}'
        .format(url=highlight_js_url, token=csrf_token, zip=highlight_js_zip),  # pylint: disable=line-too-long
        f'unzip {highlight_js_zip} -d {highlight_js_dir}'
    ]
    execute_commands_and_raise_on_return_code(commands, error='Failed to set up highlight.js')
    Path(highlight_js_zip).unlink()


def _create_directory_for_authentication():  # pylint: disable=invalid-name
    logging.info('Creating directory for authentication')

    config = load_main_config()
    dburi = config.get('data-storage', 'user-database')
    # pylint: disable=fixme
    factauthdir = '/'.join(dburi.split('/')[:-1])[10:]  # FIXME this should be beautified with pathlib

    mkdir_process = subprocess.run(
        f'sudo mkdir -p --mode=0744 {factauthdir}', shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True
    )
    chown_process = subprocess.run(
        f'sudo chown {os.getuid()}:{os.getgid()} {factauthdir}',
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        universal_newlines=True
    )

    if not all(return_code == 0 for return_code in [mkdir_process.returncode, chown_process.returncode]):
        raise InstallationError(
            'Error in creating directory for authentication database.\n{}'.format(
                '\n'.join((mkdir_process.stdout, mkdir_process.stdout))
            )
        )


def _install_nginx(distribution):
    if distribution != 'fedora':
        apt_install_packages('nginx')
    else:
        dnf_install_packages('nginx')
    _generate_and_install_certificate()
    _configure_nginx()
    if distribution == 'fedora':
        execute_commands_and_raise_on_return_code(
            [
                'sudo restorecon -v /etc/nginx/fact.*',
                'sudo semanage fcontext -at httpd_log_t "/var/log/fact(/.*)?" || true',
                'sudo restorecon -v -R /var/log/fact'
            ],
            error='restore selinux context'
        )
    nginx_process = subprocess.run(
        'sudo nginx -s reload', shell=True, stdout=PIPE, stderr=PIPE, universal_newlines=True
    )
    if nginx_process.returncode != 0:
        raise InstallationError(f'Failed to start nginx\n{nginx_process.stderr}')


def _generate_and_install_certificate():
    logging.info('Generating self-signed certificate')
    execute_commands_and_raise_on_return_code(
        [
            'openssl genrsa -out fact.key 4096',
            f'echo "{DEFAULT_CERT}" | openssl req -new -key fact.key -out fact.csr',
            'openssl x509 -req -days 730 -in fact.csr -signkey fact.key -out fact.crt',
            'sudo mv fact.key fact.csr fact.crt /etc/nginx'
        ],
        error='generate SSL certificate'
    )


def _configure_nginx():
    logging.info('Configuring nginx')
    execute_commands_and_raise_on_return_code(
        [
            'sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak',
            'sudo rm /etc/nginx/nginx.conf',  # copy is better on redhat to respect selinux context
            '(cd ../config && sudo install -m 644 $PWD/nginx.conf /etc/nginx/nginx.conf)',
            '(sudo mkdir /etc/nginx/error || true)',
            '(cd ../web_interface/templates/ && sudo ln -s $PWD/maintenance.html /etc/nginx/error/maintenance.html) || true'
        ],
        error='configuring nginx'
    )


def _install_css_and_js_files():
    with OperateInDirectory('../web_interface/static'):
        os.makedirs('web_css', exist_ok=True)
        os.makedirs('web_js', exist_ok=True)

        wget_static_web_content(
            'https://github.com/vakata/jstree/zipball/3.3.9',
            '.', ['unzip 3.3.9', 'rm 3.3.9', 'rm -rf ./web_js/jstree/vakata*', 'mv vakata* web_js/jstree'],
            'jstree'
        )
        wget_static_web_content(
            'https://ajax.googleapis.com/ajax/libs/angularjs/1.4.8/angular.min.js', '.', [], 'angularJS'
        )
        wget_static_web_content(
            'https://github.com/chartjs/Chart.js/releases/download/v2.3.0/Chart.js', '.', [], 'charts.js'
        )

        _build_highlight_js()

        for css_url in [
            'https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css',
            'https://cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/1.8.0/css/bootstrap-datepicker.standalone.css',
            'https://unpkg.com/vis-network@8.5.6/styles/vis-network.min.css',
            'https://cdn.jsdelivr.net/npm/diff2html/bundles/css/diff2html.min.css',
            'https://cdn.jsdelivr.net/npm/bootstrap-select@1.13.14/dist/css/bootstrap-select.min.css',
        ]:
            wget_static_web_content(css_url, 'web_css', [])

        for js_url in [
            'https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.1/jquery.min.js',
            'https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js',
            'https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js',
            'https://cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/1.8.0/js/bootstrap-datepicker.js',
            'https://raw.githubusercontent.com/moment/moment/develop/moment.js',
            'https://unpkg.com/vis-network@8.5.6/standalone/umd/vis-network.min.js',
            'https://cdn.jsdelivr.net/npm/diff2html/bundles/js/diff2html-ui.min.js',
            'https://cdn.jsdelivr.net/npm/bootstrap-select@1.13.14/dist/js/bootstrap-select.min.js',
        ]:
            wget_static_web_content(js_url, 'web_js', [])

        if not Path('web_css/fontawesome').exists():
            wget_static_web_content(
                'https://use.fontawesome.com/releases/v5.13.0/fontawesome-free-5.13.0-web.zip',
                '.',
                [
                    'unzip fontawesome-free-5.13.0-web.zip',
                    'rm fontawesome-free-5.13.0-web.zip',
                    'mv fontawesome-free-5.13.0-web web_css/fontawesome'
                ]
            )


def _install_docker_images(radare):
    if radare:
        logging.info('Initializing docker container for radare')

        with OperateInDirectory('radare'):
            docker_compose_process = subprocess.run(
                'docker-compose build', shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True
            )
            if docker_compose_process.returncode != 0:
                raise InstallationError(f'Failed to initialize radare container:\n{docker_compose_process.stdout}')

    # pull pdf report container
    logging.info('Pulling pdf report container')
    docker_process = subprocess.run(
        'docker pull fkiecad/fact_pdf_report', shell=True, stdout=PIPE, stderr=STDOUT, universal_newlines=True
    )
    if docker_process.returncode != 0:
        raise InstallationError(f'Failed to pull pdf report container:\n{docker_process.stdout}')


def main(skip_docker, radare, nginx, distribution):
    # flask-security is not maintained anymore and replaced by flask-security-too.
    # Since python package naming conflicts are not resolved automatically, we remove flask-security manually.
    run_cmd_with_logging('sudo -EH pip3 uninstall -y flask-security')
    install_pip_packages(PIP_DEPENDENCIES)

    # installing web/js-frameworks
    _install_css_and_js_files()

    # create user database
    _create_directory_for_authentication()

    if nginx:
        _install_nginx(distribution)

    if not skip_docker:
        _install_docker_images(radare)

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_fact_frontend').unlink()
        Path('start_fact_frontend').symlink_to('src/start_fact_frontend.py')

    return 0
