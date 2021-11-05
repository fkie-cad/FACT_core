function hide_checkbox() {
    if ($("#only_firmware").is(':checked')) {
        $("#inverted_div").show();
    } else {
        $("#inverted_div").hide();
    }
}