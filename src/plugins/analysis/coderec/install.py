import logging
from pathlib import Path

try:
    from helperFunctions.install import run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller
except ImportError:
    import sys

    SRC_PATH = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_PATH))

    from helperFunctions.install import run_cmd_with_logging
    from plugins.installer import AbstractPluginInstaller


class CodeRecPluginInstaller(AbstractPluginInstaller):
    base_path = Path(__file__).resolve().parent

    def install_docker_images(self):
        run_cmd_with_logging(f'docker build -t fact/coderec {self.base_path}/docker')


# Alias for generic use
Installer = CodeRecPluginInstaller

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Installer().install()
