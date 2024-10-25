const preview_loading_gif = document.getElementById("preview-loading-gif");
const preview_button = document.getElementById("preview_button");
const offset_input = document.getElementById("hex-preview-offset");

function hide_gif(element) {
    element.style.display = "none";
}
function init_preview() {
    hide_gif(preview_loading_gif);
    if (isTextOrImage) {
        highlight_code();
    }
    preview_button.scrollIntoView();
    offset_input.focus();
}
function highlight_code() {
    const block = $('div#preview-div pre')[0];
    hljs.highlightElement(block);
    line_numbering();
}
function load_preview(offset = null, focus = false) {
    let resourcePath;
    document.getElementById("preview_button").onclick = () => false;
    if (focus && offset !== null) {
        document.getElementById("preview-div").classList.add("show");
        offset_input.value = offset;
    }
    if (isTextOrImage) {
        resourcePath = `/ajax_get_binary/${mimeType}/${uid}`;
    } else {
        // hex preview
        offset_input.classList.remove("is-invalid");
        $("#preview-content").html("");
        document.getElementById("hex-preview-form").style.display = "flex";
        let offset = parseInt(offset_input.value);
        if (isNaN(offset)) {
            offset_input.classList.add("is-invalid");
            return;
        }
        let length = document.getElementById("hex-preview-length").value;
        resourcePath = `/ajax_get_hex_preview/${uid}/${offset}/${length}`;
    }
    preview_loading_gif.style.display = "block";
    $("#preview-content").load(resourcePath, init_preview);
}
preview_button.onclick = load_preview;
let rawResultIsHighlighted = false;
const toggleSwitch = document.getElementById("rawResultSwitch");

toggleSwitch.addEventListener('change', function() {
    const analysisTable = document.getElementById("analysis-table-body");
    const rawResultRow = document.getElementById("raw-result");
    const analysisRows = Array.from(analysisTable.children)
        .filter(child => !child.classList.contains("analysis-meta"));

    if (toggleSwitch.checked) {
        analysisRows.forEach((element) => {
            element.style.visibility = "collapse";
        });
        rawResultRow.style.visibility = "visible";
    } else {
        analysisRows.forEach((element) => {
            element.style.visibility = "visible";
        });
        rawResultRow.style.visibility = "collapse";
    }

    if (!rawResultIsHighlighted && toggleSwitch.checked) {
        // highlight the result lazily and only once
        rawResultIsHighlighted = true;
        let rawResult = document.getElementById('raw-analysis');
        hljs.highlightBlock(rawResult);
    }
});

window.onload = function() {
    // make sure the switch is off when the page is reloaded
    toggleSwitch.checked = false;
};

function copyRawAnalysis() {
    const code = document.getElementById("raw-analysis");
    // Copy the raw analysis data to clipboard
    navigator.clipboard.writeText(code.textContent);
}
