function hide_summary_gif() {
    loading_gif.style.display = "none";
}
function load_summary(uid, selected_analysis){
    $("#summary-div").load(`/ajax_get_summary/${uid}/${selected_analysis}`, hide_summary_gif);
}
$(document).ready(function() {
    load_summary(uid, selected_analysis);
});