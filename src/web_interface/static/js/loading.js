function showImg() {
    $('#form').hide();
    $('#loading-img').css({'display': 'block'});
}

function hideImg() {
    $('#form').show();
    $('#loading-img').css({'display': 'none'});
}

function loadLoadingAnimation(elementId) {
    fetch("/static/fact_loading.svg")
    .then(response => response.text())
    .then(data => {
        document.getElementById(elementId).innerHTML = data;
    })
    .catch(error => {
        console.error('Error loading loading animation:', error);
    });
}
