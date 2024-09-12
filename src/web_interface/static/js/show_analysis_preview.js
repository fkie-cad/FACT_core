const preview_loading_gif = document.getElementById("preview-loading-gif");
function hide_gif(element) {
    element.style.display = "none";
}
function init_preview() {
    hide_gif(preview_loading_gif);
    if (isTextOrImage) {
        highlight_code();
    }
}
function highlight_code() {
    const block = $('div#preview-div pre')[0];
    hljs.highlightElement(block);
    line_numbering();
}
function load_preview() {
    let resourcePath;
    document.getElementById("preview_button").onclick = () => { return false; };
    if (isTextOrImage) {
        resourcePath = `/ajax_get_binary/${mimeType}/${uid}`;
    } else {
        // hex preview
        if ($("#hex-preview-offset").hasClass("is-invalid")) {
            $("#hex-preview-offset").removeClass("is-invalid");
        }
        $("#preview-content").html("");
        document.getElementById('hex-preview-form').style.display = "flex";
        let offset = parseInt(document.getElementById('hex-preview-offset').value);
        if (isNaN(offset)) {
            $("#hex-preview-offset").addClass("is-invalid");
            return;
        }
        let length = document.getElementById('hex-preview-length').value;
        resourcePath = `/ajax_get_hex_preview/${uid}/${offset}/${length}`;
    }
    preview_loading_gif.style.display = "block";
    $("#preview-content").load(resourcePath, init_preview);
}
document.getElementById("preview_button").onclick = load_preview;
let rawIsVisible = false;
let rawResultIsHighlighted = false;

function toggleRawResult() {
    const analysisTable = document.getElementById("analysis-table-body");
    const rawResultRow = document.getElementById("raw-result");
    // filter out meta rows
    const analysisRows = Array.from(analysisTable.children)
        .filter(child => !child.classList.contains("analysis-meta"));
    if (rawIsVisible) {
        analysisRows.forEach((element) => {
            element.style.visibility = "visible";
        });
        rawResultRow.style.visibility = "collapse";
    } else {
        analysisRows.forEach((element) => {
            element.style.visibility = "collapse";
        });
        rawResultRow.style.visibility = "visible";
    }
    rawIsVisible = !rawIsVisible;

    if (!rawResultIsHighlighted) {
        rawResultIsHighlighted = true;
        let rawResult = document.getElementById('raw-analysis');
        hljs.highlightBlock(rawResult);
    }
}
