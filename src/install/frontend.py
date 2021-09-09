import logging
import os
from contextlib import suppress
from pathlib import Path

import requests
from common_helper_process import execute_shell_command_get_return_code

from helperFunctions.install import (
    InstallationError, OperateInDirectory, apt_install_packages, load_main_config, remove_folder, run_cmd_with_logging
)

DEFAULT_CERT = '.\n.\n.\n.\n.\nexample.com\n.\n\n\n'
COMPOSE_VENV = Path(__file__).parent.absolute() / 'compose-env'


def execute_commands_and_raise_on_return_code(commands, error=None):  # pylint: disable=invalid-name
    for command in commands:
        bad_return = error if error else 'execute {}'.format(command)
        output, return_code = execute_shell_command_get_return_code(command)
        if return_code != 0:
            raise InstallationError('Failed to {}\n{}'.format(bad_return, output))


def wget_static_web_content(url, target_folder, additional_actions, resource_logging_name=None):
    logging.info('Install static {} content'.format(resource_logging_name if resource_logging_name else url))
    with OperateInDirectory(target_folder):
        wget_output, wget_code = execute_shell_command_get_return_code('wget -nc {}'.format(url))
        if wget_code != 0:
            raise InstallationError('Failed to fetch resource at {}\n{}'.format(url, wget_output))
        for action in additional_actions:
            action_output, action_code = execute_shell_command_get_return_code(action)
            if action_code != 0:
                raise InstallationError('Problem in processing resource at {}\n{}'.format(url, action_output))


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
        'wget {url} --header="Host: highlightjs.org" --header="User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0" --header="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" --header="Accept-Language: en-GB,en;q=0.5" --header="Accept-Encoding: gzip, deflate, br" --header="Referer: https://highlightjs.org/download/" --header="Content-Type: application/x-www-form-urlencoded" --header="Cookie: csrftoken={token}" --header="DNT: 1" --header="Connection: keep-alive" --header="Upgrade-Insecure-Requests: 1" --post-data="apache.js=on&bash.js=on&coffeescript.js=on&cpp.js=on&cs.js=on&csrfmiddlewaretoken={token}&css.js=on&diff.js=on&http.js=on&ini.js=on&java.js=on&javascript.js=on&json.js=on&makefile.js=on&markdown.js=on&nginx.js=on&objectivec.js=on&perl.js=on&php.js=on&python.js=on&ruby.js=on&shell.js=on&sql.js=on&xml.js=on" -O {zip}'.format(url=highlight_js_url, token=csrf_token, zip=highlight_js_zip),  # pylint: disable=line-too-long
        'unzip {} -d {}'.format(highlight_js_zip, highlight_js_dir)
    ]
    execute_commands_and_raise_on_return_code(commands, error='Failed to set up highlight.js')
    Path(highlight_js_zip).unlink()


def _create_directory_for_authentication():  # pylint: disable=invalid-name
    logging.info('Creating directory for authentication')

    config = load_main_config()
    dburi = config.get('data_storage', 'user_database')
    # pylint: disable=fixme
    factauthdir = '/'.join(dburi.split('/')[:-1])[10:]  # FIXME this should be beautified with pathlib

    mkdir_output, mkdir_code = execute_shell_command_get_return_code('sudo mkdir -p --mode=0744 {}'.format(factauthdir))
    chown_output, chown_code = execute_shell_command_get_return_code('sudo chown {}:{} {}'.format(os.getuid(), os.getgid(), factauthdir))

    if not all(return_code == 0 for return_code in [mkdir_code, chown_code]):
        raise InstallationError('Error in creating directory for authentication database.\n{}'.format('\n'.join((mkdir_output, chown_output))))


def _install_nginx():
    apt_install_packages('nginx')
    _generate_and_install_certificate()
    _configure_nginx()
    nginx_output, nginx_code = execute_shell_command_get_return_code('sudo nginx -s reload')
    if nginx_code != 0:
        raise InstallationError('Failed to start nginx\n{}'.format(nginx_output))


def _generate_and_install_certificate():
    logging.info("Generating self-signed certificate")
    execute_commands_and_raise_on_return_code([
        'openssl genrsa -out fact.key 4096',
        'echo "{}" | openssl req -new -key fact.key -out fact.csr'.format(DEFAULT_CERT),
        'openssl x509 -req -days 730 -in fact.csr -signkey fact.key -out fact.crt',
        'sudo mv fact.key fact.csr fact.crt /etc/nginx'
    ], error='generate SSL certificate')


def _configure_nginx():
    logging.info("Configuring nginx")
    execute_commands_and_raise_on_return_code([
        'sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak',
        'sudo rm /etc/nginx/nginx.conf',
        '(cd ../config && sudo ln -s $PWD/nginx.conf /etc/nginx/nginx.conf)',
        '(sudo mkdir /etc/nginx/error || true)',
        '(cd ../web_interface/templates/ && sudo ln -s $PWD/maintenance.html /etc/nginx/error/maintenance.html) || true'
    ], error='configuring nginx')


def _install_css_and_js_files():
    with OperateInDirectory('../web_interface/static'):
        os.makedirs('web_css', exist_ok=True)
        os.makedirs('web_js', exist_ok=True)

        wget_static_web_content('https://github.com/vakata/jstree/zipball/3.3.9', '.', ['unzip 3.3.9', 'rm 3.3.9', 'rm -rf ./web_js/jstree/vakata*', 'mv vakata* web_js/jstree'], 'jstree')
        wget_static_web_content('https://ajax.googleapis.com/ajax/libs/angularjs/1.4.8/angular.min.js', '.', [], 'angularJS')
        wget_static_web_content('https://github.com/chartjs/Chart.js/releases/download/v2.3.0/Chart.js', '.', [], 'charts.js')
        wget_static_web_content('https://registry.npmjs.org/vis-network/-/vis-network-8.5.2.tgz', '.', ['tar xf vis-network-8.5.2.tgz', 'rm -rf vis', 'mv package/dist vis'], 'vis-network')

        _build_highlight_js()

        for css_url in [
                'https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css',
                'https://cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/1.8.0/css/bootstrap-datepicker.standalone.css'
        ]:
            wget_static_web_content(css_url, 'web_css', [])

        for js_url in [
                'https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.1/jquery.min.js',
                'https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js',
                'https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js',
                'https://cdnjs.cloudflare.com/ajax/libs/bootstrap-datepicker/1.8.0/js/bootstrap-datepicker.js',
                'https://raw.githubusercontent.com/moment/moment/develop/moment.js'
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

        execute_shell_command_get_return_code('virtualenv {}'.format(COMPOSE_VENV))
        # We use the pip from the Venv for docker-compose
        output, return_code = execute_shell_command_get_return_code('{} install -U docker-compose'.format(COMPOSE_VENV / 'bin' / 'pip'))
        if return_code != 0:
            raise InstallationError('Failed to set up virtualenv for docker-compose\n{}'.format(output))

        with OperateInDirectory('radare'):
            output, return_code = execute_shell_command_get_return_code('{} build'.format(COMPOSE_VENV / 'bin' / 'docker-compose'))
            if return_code != 0:
                raise InstallationError('Failed to initialize radare container:\n{}'.format(output))

    # pull pdf report container
    logging.info('Pulling pdf report container')
    output, return_code = execute_shell_command_get_return_code('docker pull fkiecad/fact_pdf_report')
    if return_code != 0:
        raise InstallationError('Failed to pull pdf report container:\n{}'.format(output))


def main(skip_docker, radare, nginx):
    run_cmd_with_logging("sudo -EH pip3 install -r ./requirements_frontend.txt")

    # installing web/js-frameworks
    _install_css_and_js_files()

    # create user database
    _create_directory_for_authentication()

    if nginx:
        _install_nginx()

    if not skip_docker:
        _install_docker_images(radare)

    with OperateInDirectory('../../'):
        with suppress(FileNotFoundError):
            Path('start_fact_frontend').unlink()
        Path('start_fact_frontend').symlink_to('src/start_fact_frontend.py')

    return 0
