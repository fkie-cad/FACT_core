from test.common_helper import get_config_for_testing
from web_interface.components.io_routes import IORoutes


def test_get_radare_endpoint():
    config = get_config_for_testing()

    assert config.get('expert-settings', 'nginx') == 'false'
    assert IORoutes._get_radare_endpoint(config) == 'http://localhost:8000'  # pylint: disable=protected-access

    config.set('expert-settings', 'nginx', 'true')
    assert IORoutes._get_radare_endpoint(config) == 'https://localhost/radare'  # pylint: disable=protected-access
