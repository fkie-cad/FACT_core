$('#fileTreeAjax')
    // generate links to the analysis page
    .on("activate_node.jstree", function(e,data){window.location.href = data.node.a_attr.href;})
    // generate file tree
    .jstree({
        "core" : {
            'data' : {
                'url' : function (node) {
                    return node.id === '#' ?
                        `/ajax_root/${uid}/${root_uid}` : "/ajax_tree/" + node["data"]["uid"] + `/${root_uid}`;
                }
            }
        },
        "plugins" : [ "sort" ]
    });