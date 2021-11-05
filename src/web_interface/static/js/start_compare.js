function start_compare(){
    var checkbox = document.getElementById('recompare_checkbox');
    var link = '/compare';
    if (checkbox.checked) link += '?force_recompare=true';
    location.href = link;
};