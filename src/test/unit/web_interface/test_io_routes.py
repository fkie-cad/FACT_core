from web_interface.components.io_routes import IORoutes


def test_get_radare_endpoint(cfg_tuple):
    _, configparser_cfg = cfg_tuple
    assert configparser_cfg.get('expert-settings', 'nginx') == 'false'
    assert IORoutes._get_radare_endpoint(configparser_cfg) == 'http://localhost:8000'  # pylint: disable=protected-access

    configparser_cfg.set('expert-settings', 'nginx', 'true')
    assert IORoutes._get_radare_endpoint(configparser_cfg) == 'https://localhost/radare'  # pylint: disable=protected-access
