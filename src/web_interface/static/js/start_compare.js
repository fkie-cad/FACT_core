function start_compare(){
    var checkbox = document.getElementById('recompare_checkbox');
    var link = '/compare';
    if (checkbox.checked) link += '?force_recompare=true';
    location.href = link;
}
document.getElementById("start_compare_button").onclick = start_compare;

function start_text_file_compare(){
    var link = '/comparison/text_files';
    location.href = link;
}
document.getElementById("start_text_file_compare_button").onclick = start_text_file_compare;