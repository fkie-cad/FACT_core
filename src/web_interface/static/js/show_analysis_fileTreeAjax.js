// source: https://stackoverflow.com/questions/1909441/how-to-delay-the-keyup-handler-until-the-user-stops-typing
function delay(fn, ms) {
    let timer = 0;
    return function(...args) {
        clearTimeout(timer);
        timer = setTimeout(fn.bind(this, ...args), ms || 0);
    };
}

$(document).ready(function () {
    let fileTree = create_file_tree(
        $('#fileTreeAjax'),
        true,
        (node) => node.id === '#' ?
            // root node url
            `/ajax_root/${uid}/${root_uid}` :
            // inner node url
            `/ajax_tree/${node.data.uid}/${root_uid}`
    );
    // start file tree search on keyup event
    $('#fileTreeSearch').keyup(delay(function () {
        fileTree.jstree(true).show_all();
        fileTree.jstree('search', $(this).val());
        $('#fileTreeAjax .jstree-hidden').hide();
    }, 1000));
    // display error if file tree search yielded no results
    fileTree.on('search.jstree', (nodes, str, res) => {
        if (str.nodes.length === 0) {
            $("#fileTreeAjax").jstree(true).hide_all();
            $("#fileTreeSearch").addClass("is-invalid");
            $("#fileTreeSearchFeedback").show();
        } else {
            $("#fileTreeSearch").removeClass("is-invalid");
            $("#fileTreeSearchFeedback").hide();
        }
    });
});
