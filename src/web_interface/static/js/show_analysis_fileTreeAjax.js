$('#fileTreeAjax')
    // generate links to the analysis page
    .on("activate_node.jstree", function(e,data){window.location.href = data.node.a_attr.href;})
    // generate file tree
    .jstree({
        "core" : {
            'data' : {
                'url' : function (node) {
                    return node.id === '#' ?
                        `/ajax_root/${uid}/${root_uid}` : "/ajax_tree/" + node.data.uid + `/${root_uid}`;
                }
            },
            'themes': {
                'name': 'proton',
                'responsive': true,
            },
        },
        "search": {
            "case_insensitive": false,
            "show_only_matches": true,
        },
        "plugins" : [ "sort", "themes", "search" ]
    }).on('search.jstree', function (nodes, str, res) {
        if (str.nodes.length === 0) {
            $("#fileTreeAjax").jstree(true).hide_all();
            $("#fileTreeSearch").addClass("is-invalid");
        } else {
            $("#fileTreeSearch").removeClass("is-invalid");
        }
    });
$(document).ready(function () {
    $('#fileTreeSearch').keyup(function () {
    $('#fileTreeAjax').jstree(true).show_all();
    $('#fileTreeAjax').jstree('search', $(this).val());
    $('#fileTreeAjax .jstree-hidden').hide();
  });
});