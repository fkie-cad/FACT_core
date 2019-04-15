$(document).ready(function(){
    $(".plugin_header").css( 'cursor', 'pointer' );
    $(".plugin_header").click(function(){
        var contentPanelId = jQuery(this).attr("id");
        $("." + contentPanelId).toggle();
    });
});    