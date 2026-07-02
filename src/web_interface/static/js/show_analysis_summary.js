function load_summary(uid, selected_analysis, inverted){
    $("#summary-button").css("display", "none");
    let summary_gif = $("#loading-summary-gif");
    summary_gif.css("display", "block");
    $("#summary-div").load(
        `/ajax_get_summary/${uid}/${selected_analysis}/${inverted}`,
        () => {
            summary_gif.css("display", "none");
        }
    );
}
