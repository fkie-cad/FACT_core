import unittest
from helperFunctions.file_tree import FileTreeNode, get_partial_virtual_path, get_correct_icon_for_mime


class TestFileTree(unittest.TestCase):
    def test_node_creation(self):
        parent_node = FileTreeNode("123", False, "parent", 1, "somefile")
        child_node = FileTreeNode("456", True, "child")
        parent_node.add_child_node(child_node)

        self.assertEqual(parent_node.uid, "123")
        self.assertFalse(parent_node.virtual)
        self.assertEqual(parent_node.size, 1)
        self.assertEqual(parent_node.type, "somefile")
        self.assertTrue(parent_node.has_children)
        self.assertEqual(parent_node.get_list_of_child_nodes(), [child_node])
        self.assertEqual(parent_node.get_id(), ("parent", False))
        self.assertEqual(list(parent_node.children.keys()), [child_node.get_id()])
        self.assertEqual(parent_node.get_names_of_children(), [child_node.name])
        self.assertFalse(child_node.has_children)
        self.assertTrue(child_node in parent_node)
        self.assertTrue(parent_node, FileTreeNode("123", False, "parent", 1, "somefile"))

    def test_node_merging(self):
        parent_node = FileTreeNode("123", False, "parent", 1, "somefile")
        child_node_folder_1 = FileTreeNode(None, True, "folder")
        child_node_folder_2 = FileTreeNode(None, True, "folder")
        child_node_file_1 = FileTreeNode("abc", False, "file_1")
        child_node_file_2 = FileTreeNode("def", False, "file_2")
        child_node_folder_1.add_child_node(child_node_file_1)
        child_node_folder_2.add_child_node(child_node_file_2)
        parent_node.add_child_node(child_node_folder_1)
        parent_node.add_child_node(child_node_folder_2)

        self.assertTrue(parent_node.has_children)
        self.assertEqual(len(parent_node.get_list_of_child_nodes()), 1)
        self.assertEqual(list(parent_node.children.keys()), [child_node_folder_1.get_id()])
        self.assertTrue(child_node_folder_1 in parent_node)
        self.assertTrue(child_node_folder_2 in parent_node)
        self.assertEqual(len(parent_node.children[child_node_folder_1.get_id()].get_list_of_child_nodes()), 2)
        folder_id = child_node_folder_1.get_id()
        self.assertTrue(child_node_file_1 in parent_node.children[folder_id])
        self.assertTrue(child_node_file_2 in parent_node.children[folder_id])

    def test_get_partial_virtual_path(self):
        virtual_path = {"abc": ["|abc|def|ghi|folder_1/folder_2/file"]}

        self.assertEqual(get_partial_virtual_path(virtual_path, "abc"),
                         {'abc': ['|abc|def|ghi|folder_1/folder_2/file']})
        self.assertEqual(get_partial_virtual_path(virtual_path, "ghi"),
                         {'ghi': ['|ghi|folder_1/folder_2/file']})
        self.assertEqual(get_partial_virtual_path(virtual_path, "xyz"),
                         {'xyz': ['|xyz|']})

    def test_get_correct_icon_for_mime(self):
        self.assertEqual(get_correct_icon_for_mime('application/zip'), "/static/file_icons/archive.png")
        self.assertEqual(get_correct_icon_for_mime("filesystem/some_filesystem"), "/static/file_icons/filesystem.png")
        self.assertEqual(get_correct_icon_for_mime("some unknown mime type"), "/static/file_icons/unknown.png")
