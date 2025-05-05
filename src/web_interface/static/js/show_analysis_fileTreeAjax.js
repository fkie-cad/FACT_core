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
    Document.fileTree = fileTree;
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
    fileTree.on('open_node.jstree', function(e, data) {
        if (!data.node.icon.includes("folder")) {
            toggleSymlinkNodes();
        }
    });
});

const symlinkSwitch = document.getElementById("symlinkSwitch");
symlinkSwitch.checked = true;

function toggleSymlinkNodes() {
    let filetree = Document.fileTree;
    filetree.jstree(true).get_json('#', { flat: true }).forEach(function(node) {
        if (node.icon.includes("inode-symlink")) {
            if (symlinkSwitch.checked === true) {
                filetree.jstree('show_node', node.id);
            } else {
                filetree.jstree('hide_node', node.id);
            }
        }
    });
}
