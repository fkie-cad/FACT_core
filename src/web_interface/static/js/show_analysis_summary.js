function load_summary(uid, selected_analysis){
    $("#summary-button").css("display", "none");
    let summary_gif = $("#loading-summary-gif");
    summary_gif.css("display", "block");
    $("#summary-div").load(
        `/ajax_get_summary/${uid}/${selected_analysis}`,
        () => {summary_gif.css("display", "none");}
    );
}
