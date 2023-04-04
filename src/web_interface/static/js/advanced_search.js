function hide_checkbox() {
    if ($("#only_firmware").is(':checked')) {
        $("#inverted_div").show();
    } else {
        $("#inverted_div").hide();
    }
}

function validateQuery() {
    const queryInput = document.getElementById('advanced_search');
    const feedback = document.getElementById('advanced_search_feedback');
    const trailing_comma_regex = /\,(?=\s*?[\}\]])/g;
    try {
        // try to parse advanced search query as JSON to see if it is valid
        // also remove trailing commas which are not legal in JSON
        const json = JSON.parse(queryInput.value.replace(trailing_comma_regex, ''));
        // format JSON query
        queryInput.value = JSON.stringify(json, undefined, 4);
        queryInput.classList.remove("is-invalid");
        queryInput.classList.add("is-valid");
        feedback.innerText = "";
        // adjust text area height to fit input
        queryInput.style.height = 0;
        queryInput.style.height = `${queryInput.scrollHeight + 1}px`;
    } catch (err) {
        queryInput.classList.remove("is-valid");
        queryInput.classList.add("is-invalid");
        // remove the start to only leave the error message
        feedback.innerText = String(err).slice(25);
        return false;
    }
    return true;
}

function submitSearch(form) {
    if (validateQuery()) {
        form.submit();
    }
}
