from common_helper_process import execute_shell_command_get_return_code


class InstallationError(Exception):
    pass


def apt_update_sources():
    output, return_code = execute_shell_command_get_return_code('sudo apt-get update')
    if return_code != 0:
        raise InstallationError('Unable to update repository sources. Check network.')
    return output


def apt_upgrade_system():
    output, return_code = execute_shell_command_get_return_code('sudo apt-get upgrade -y')
    if return_code != 0:
        raise InstallationError('Unable to upgrade packages: \n{}'.format(output))
    return output


def apt_autoremove_packages():
    output, return_code = execute_shell_command_get_return_code('sudo apt-get autoremove -y')
    if return_code != 0:
        raise InstallationError('Automatic removal of packages failed:\n{}'.format(output))
    return output


def apt_clean_system():
    output, return_code = execute_shell_command_get_return_code('sudo apt-get clean')
    if return_code != 0:
        raise InstallationError('Cleaning of package files failed:\n{}'.format(output))
    return output


def apt_install_packages(*args):
    output, return_code = execute_shell_command_get_return_code('sudo apt-get install -y {}'.format(' '.join(args)))
    if return_code != 0:
        raise InstallationError('Error in installation of package(s) {}\n{}'.format(' '.join(args), output))
    return output


def apt_remove_packages(*args):
    output, return_code = execute_shell_command_get_return_code('sudo apt-get remove -y {}'.format(' '.join(args)))
    if return_code != 0:
        raise InstallationError('Error in removal of package(s) {}\n{}'.format(' '.join(args), output))
    return output


def pip_install_packages(*args):
    output, return_code = execute_shell_command_get_return_code('sudo -EH pip3 install --upgrade {}'.format(' '.join(args)))
    if return_code != 0:
        raise InstallationError('Error in installation of python package(s) {}\n{}'.format(' '.join(args), output))
    return output


def pip_remove_packages(*args):
    pass


def check_if_command_in_path(command_with_parameters):
    pass


def check_if_executable_in_bin_folder(executable_name):
    pass
