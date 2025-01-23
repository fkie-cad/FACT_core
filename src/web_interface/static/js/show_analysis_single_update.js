// single file analysis (update)
function waitForAnalysis(url, element, formData=null) {
    // wait until the analysis is finished and then (re)load the page to show it
    element.innerHTML = `<i class="fas fa-spinner fa-fw margin-right-md fa-spin"></i> analysis in progress ...`;
    const message = 'Timeout when waiting for analysis. Please manually refresh the page.';
    fetch(url, {
        method: 'POST',
        body: formData,
        signal: AbortSignal.timeout(60000)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            console.log('Analysis successful');
            localStorage.setItem('analysisUpdated', `${selected_analysis}-${uid}`);
            if (formData != null) {
                const checkedOptions = [];
                formData.forEach((value, key) => {
                    if (key === 'analysis_systems') {
                        checkedOptions.push(value);
                    }
                });
                if (checkedOptions.length > 0 && checkedOptions.indexOf(selected_analysis) === -1) {
                    let url = window.location.href;
                    const someSelectedPlugin = checkedOptions[0];
                    localStorage.setItem('analysisUpdated', `${someSelectedPlugin}-${uid}`);
                    if (selected_analysis === 'None') {
                        // no plugin is currently selected
                        url = `/analysis/${uid}/${someSelectedPlugin}`;
                    } else {
                        // another plugin (that was not updated) is selected → replace it in the URL
                        url = url.replace(selected_analysis, someSelectedPlugin);
                    }
                    window.location.href = url;
                    return;
                }
            }
            window.location.reload();
        } else {
            console.log('Analysis failed');
            element.innerHTML = message;
        }
    })
    .catch(error => {
        console.error('Error during single file analysis:', error);
        element.innerHTML = message;
    });
}
