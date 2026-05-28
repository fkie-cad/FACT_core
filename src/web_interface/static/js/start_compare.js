function start_comparison(){
    var checkbox = document.getElementById('recompare_checkbox');
    var link = '/compare';
    if (checkbox.checked) link += '?force_recompare=true';
    location.href = link;
}
document.getElementById("start_comparison_button").onclick = start_comparison;

function start_text_file_comparison(){
    var link = '/comparison/text_files';
    location.href = link;
}
document.getElementById("start_text_file_comparison_button").onclick = start_text_file_comparison;
