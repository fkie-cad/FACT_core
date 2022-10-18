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
            "case_insensitive": true,
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

// source: https://stackoverflow.com/questions/1909441/how-to-delay-the-keyup-handler-until-the-user-stops-typing
function delay(fn, ms) {
    let timer = 0;
    return function(...args) {
        clearTimeout(timer);
        timer = setTimeout(fn.bind(this, ...args), ms || 0);
    };
}

$(document).ready(function () {
    $('#fileTreeSearch').keyup(delay(function () {
        $('#fileTreeAjax').jstree(true).show_all();
        $('#fileTreeAjax').jstree('search', $(this).val());
        $('#fileTreeAjax .jstree-hidden').hide();
    }, 1000));
});