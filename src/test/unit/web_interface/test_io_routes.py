from web_interface.components.io_routes import IORoutes
import pytest


@pytest.mark.cfg_defaults(
    {
        'expert-settings': {
            'nginx': 'false',
        }
    }
)
def test_get_radare_endpoint():
    assert IORoutes._get_radare_endpoint() == 'http://localhost:8000'  # pylint: disable=protected-access


@pytest.mark.cfg_defaults(
    {
        'expert-settings': {
            'nginx': 'true',
        }
    }
)
def test_get_radare_endpoint_nginx():
    assert IORoutes._get_radare_endpoint() == 'https://localhost/radare'  # pylint: disable=protected-access
