const BOOTSTRAP_DANGER_COLOR = "#dc3545";
const BOOTSTRAP_PRIMARY_COLOR = "#007bff";

function change_button(button_id) {
    element = document.getElementById(button_id);
    ["fa-caret-down", "fa-caret-up"].forEach(class_name => element.classList.toggle(class_name));
}

async function getSystemHealthData() {
    const response = await fetch("/ajax/system_health");
    return response.json();
}

async function updateSystemHealth() {
    getSystemHealthData().then(data => data.systemHealth.map(entry => {
        const statusElement = document.getElementById(`${entry._id}-status`);
        statusElement.innerText = entry.status;
        if (entry.status == "offline") {
            statusElement.classList.add('text-danger');
            statusElement.classList.remove('text-success');
            return;
        }
        statusElement.classList.remove('text-danger');
        statusElement.classList.add('text-success');
        document.getElementById(`${entry._id}-os`).innerText = entry.platform.os;
        document.getElementById(`${entry._id}-python`).innerText = entry.platform.python;
        document.getElementById(`${entry._id}-version`).innerText = entry.platform.fact_version;
        document.getElementById(`${entry._id}-cpu`).innerText = `${entry.system.cpu_cores} cores (${entry.system.virtual_cpu_cores} threads) @ ${entry.system.cpu_percentage}%`;
        updateProgressBarElement(`${entry._id}-memory`, entry.system.memory_percent, entry.system.memory_used, entry.system.memory_total);
        updateProgressBarElement(`${entry._id}-disk`, entry.system.disk_percent, entry.system.disk_used, entry.system.disk_total);
        if (entry._id == "backend") {
            const queueElement = document.getElementById("backend-unpacking-queue");
            if (entry.unpacking.unpacking_queue > 500) {
                queueElement.classList.add("text-warning");
            }
            queueElement.innerText = entry.unpacking.unpacking_queue.toString();
            Object.entries(entry.analysis.plugins).map(([pluginName, pluginData], index) => {
                if (!pluginName.includes("dummy")){
                    updatePluginCard(pluginName, pluginData);
                }
            });
            updateCurrentAnalyses(entry.analysis);
        }
    }));
}

function updateProgressBarElement(elementId, percent, used, total) {
    const element = document.getElementById(elementId);
    element.innerHTML = getProgressBar(percent.toFixed(1), (used / Math.pow(2, 30)).toFixed(2), (total / Math.pow(2, 30)).toFixed(2), "GiB");
}

function getProgressBar(percentage, labelCurrent, labelMax, unit) {
    const value = `${labelCurrent} ${unit} / ${labelMax} ${unit}`;
    return `
        <div class="progress-bar text-center${percentage > 80 ? " bg-warning" : ""}" role="progressbar" style="width: ${percentage}%">
            ${percentage >= 50 ? value : ""}
        </div>
        &nbsp;&nbsp;${percentage < 50 ? value : ""}
    `;
}

function updatePluginCard(pluginName, pluginData) {
    const activeIndicatorElement = document.getElementById(`${pluginName}-active-indicator`);
    if (activeIndicatorElement == null) {
        console.log(`Error: Element ${pluginName}-active-indicator not found`);
        return null;
    }
    const activeElement = document.getElementById(`${pluginName}-active`);
    const queueIndicatorElement = document.getElementById(`${pluginName}-queue-indicator`);
    const queueElement = document.getElementById(`${pluginName}-queue`);
    if (pluginData.active > 0) {
        activeIndicatorElement.classList.add("fa-spin");
        activeIndicatorElement.style.color = BOOTSTRAP_PRIMARY_COLOR;
        activeElement.style.color = BOOTSTRAP_PRIMARY_COLOR;
    } else {
        activeIndicatorElement.classList.remove("fa-spin");
        activeIndicatorElement.style.color = "darkgrey";
        activeElement.style.color = "darkgrey";
    }
    activeElement.innerText = pluginData.active.toString();
    if (pluginData.queue > 100) {
        queueIndicatorElement.style.color = BOOTSTRAP_DANGER_COLOR;
        queueElement.style.color = BOOTSTRAP_DANGER_COLOR;
    } else if (pluginData.queue > 0) {
        queueIndicatorElement.style.color = "black";
        queueElement.style.color = "black";
    } else {
        queueIndicatorElement.style.color = "darkgrey";
        queueElement.style.color = "darkgrey";
    }
    queueElement.innerText = pluginData.queue.toString();
}

function updateCurrentAnalyses(analysisData) {
    const currentAnalyses = analysisData.current_analyses;
    const currentAnalysesElement = document.getElementById("current-analyses");
    const currentAnalysesHTML = [].concat(
        Object.entries(analysisData.current_analyses)
            .map(([uid, analysisStats], index) => createCurrentAnalysisItem(uid, analysisStats)),
        Object.entries(analysisData.recently_finished_analyses)
            .map(([uid, analysisStats], index) => createFinishedAnalysisItem(uid, analysisStats)),
    ).join("\n");
    currentAnalysesElement.innerHTML = currentAnalysesHTML != "" ? currentAnalysesHTML : "No analysis in progress";
}

function createCurrentAnalysisItem(uid, data) {
    const currentAnalysisProgress = data.analyzed_count / data.total_count;
    const currentUnpackingProgress = (data.unpacked_count - data.analyzed_count) / data.total_count;
    const analysisProgressString = `${data.analyzed_count} / ${data.total_count} (Elapsed: ${getDuration(data.start_time)})`;
    return `
        <div class="card clickable mt-2" onclick="location.href='/analysis/${uid}/ro/${uid}'">
            <h6 class="card-title p-2" style="margin-bottom: 0 !important; padding-bottom: 0 !important;">${data.hid}</h6>
            <div class="card-body p-2">
                ${getProgressParagraph(analysisProgressString)}
                <div class="progress" style="height: 20px;">
                    <div
                        class="progress-bar progress-bar-striped progress-bar-animated text-center"
                        role="progressbar"
                        style="width: ${currentAnalysisProgress * 100}%"
                    >
                    </div>
                    <div
                        class="progress-bar progress-bar-striped progress-bar-animated bg-warning text-center"
                        role="progressbar"
                        style="width: ${currentUnpackingProgress * 100}%"
                    ></div>
                </div>
            </div>
        </div>
    `;
}

function createFinishedAnalysisItem(uid, data) {
    const progressString = `${data.total_files_count} / ${data.total_files_count} (Finished in: ${getDuration(null, data.duration)})`;
    return `
        <div class="card clickable mt-2" onclick="location.href='/analysis/${uid}/ro/${uid}'">
            <h6 class="card-title p-2" style="margin-bottom: 0 !important; padding-bottom: 0 !important;">${data.hid}</h6>
            <div class="card-body p-2">
                ${getProgressParagraph(progressString)}
                <div class="progress" style="height: 20px;">
                    <div class="progress-bar progress-bar-striped bg-success text-center" role="progressbar" style="width: 100%"></div>
                </div>
            </div>
        </div>
    `;
}

function getProgressParagraph(progressText) {
    return `<p style="color: white; position: absolute; z-index: 3; width: 100%; margin-top: -3px; text-align: center; padding-right: 15px;"><small>${progressText}</small></p>`;
}

function getDuration(start=null, duration=null) {
    duration = duration != null ? duration : Date.now()/1000 - start;
    const date = new Date(duration * 1000);
    if (date.getUTCHours() > 0) {
        return date.toUTCString().slice(-12, -4);  // returns something like '01:23:45'
    } else {
        return date.toUTCString().slice(-9, -4);  // returns something like '23:45'
    }
}
