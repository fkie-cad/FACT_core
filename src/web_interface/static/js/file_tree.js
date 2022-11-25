function create_file_tree(div_element, search, url_function) {
    const config = {
        "core": {
            'data': {
                'url': url_function,
            },
            'themes': {
                'name': 'proton',
                'responsive': true,
            },
        },
        "search": {
            "case_insensitive": true,
            "show_only_matches": true,
        },
        "plugins": search ? ["sort", "themes", "search"] : ["sort", "themes"],
    };
    // generate links to the analysis page
    div_element.on("activate_node.jstree", (e,data) => { window.location.href = data.node.a_attr.href; });
    // generate file tree
    div_element.jstree(config);
    return div_element;
}
