function load_summary(uid, selected_analysis, reversed_order, focus=false){
    $("#summary-button").css("display", "none");
    let summary_gif = $("#loading-summary-gif");
    summary_gif.css("display", "block");
    $("#summary-div").load(
        `/ajax_get_summary/${uid}/${selected_analysis}/${reversed_order}`,
        () => {
            summary_gif.css("display", "none");
            if (focus === true) {
                location.href = "#summary-heading";
            }
        }
    );
}
