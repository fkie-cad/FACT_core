from fact.storage.db_interface_view_sync import ViewReader, ViewUpdater

TEST_TEMPLATE = b'<html><body><h1>Test Template</hi></body></html>'


def test_view_sync_interface():
    updater = ViewUpdater()
    reader = ViewReader()

    assert reader.get_view('foo') is None

    updater.update_view('foo', TEST_TEMPLATE)

    assert reader.get_view('foo') == TEST_TEMPLATE
