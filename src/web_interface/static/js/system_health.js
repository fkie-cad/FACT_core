async function getSystemHealthData() {
    const response = await fetch("/ajax/system_health");
    return response.json();
}

async function updateSystemHealth() {
    getSystemHealthData().then(data => data.systemHealth.map(entry => {
        const statusElement = document.getElementById(`${entry._id}-status`);
        statusElement.innerText = entry.status;
        if (entry.status === "offline") {
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
        if (entry._id === "backend") {
            const queueElement = document.getElementById("backend-unpacking-queue");
            if (entry.unpacking.unpacking_queue > 500) {
                queueElement.classList.add("text-warning");
            } else {
                queueElement.classList.remove("text-warning");
            }
            queueElement.innerText = entry.unpacking.unpacking_queue.toString();

            const throttleElement = document.getElementById("backend-unpacking-throttle-indicator");
            if (entry.unpacking.is_throttled) {
                throttleElement.innerHTML = '<i class="far fa-pause-circle fa-lg"></i>';
            } else {
                throttleElement.innerHTML = '';
            }

            const analysisQueueElement = document.getElementById("backend-analysis-queue");
            analysisQueueElement.innerText = entry.analysis.analysis_main_scheduler.toString();

            Object.entries(entry.analysis.plugins).map(([pluginName, pluginData], index) => {
                if (!pluginName.includes("dummy")) {
                    updatePluginCard(pluginName, pluginData);
                }
            });
            updateCurrentAnalyses(data.analysisStatus);
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
        <div class="progress-bar text-center${percentage > 80 ? " bg-warning" : ""}" role="progressbar" style="width: ${percentage}%"></div>
        <div class="justify-content-center d-flex position-absolute w-100" style="margin-top: 10px;">
            ${value}
        </div>
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
    const outQueueElement = document.getElementById(`${pluginName}-out-queue`);
    if (pluginData.active > 0) {
        activeIndicatorElement.classList.add("fa-spin");
        activeIndicatorElement.classList.remove("text-muted");
        activeIndicatorElement.classList.add("text-primary");
        activeElement.classList.remove("text-muted");
        activeElement.classList.add("text-primary");
    } else {
        activeIndicatorElement.classList.remove("fa-spin");
        activeIndicatorElement.classList.remove("text-primary");
        activeIndicatorElement.classList.add("text-muted");
        activeElement.classList.remove("text-primary");
        activeElement.classList.add("text-muted");
    }
    activeElement.innerText = pluginData.active.toString();
    if (pluginData.queue > 100) {
        queueIndicatorElement.classList.remove("text-muted");
        queueIndicatorElement.classList.add("text-danger");
        queueElement.classList.remove("text-muted");
        queueElement.classList.add("text-danger");
    } else if (pluginData.queue > 0) {
        queueIndicatorElement.classList.remove("text-muted");
        queueIndicatorElement.classList.remove("text-danger");
        queueElement.classList.remove("text-muted");
        queueElement.classList.remove("text-danger");
    } else {
        queueIndicatorElement.classList.remove("text-danger");
        queueIndicatorElement.classList.add("text-muted");
        queueElement.classList.remove("text-danger");
        queueElement.classList.add("text-muted");
    }
    queueElement.innerText = pluginData.queue.toString();
    outQueueElement.innerText = pluginData.out_queue.toString();
    updatePluginRuntimeStatsTooltip(pluginData, pluginName);
}

function updatePluginRuntimeStatsTooltip(pluginData, pluginName) {
    const stats = getPluginRuntimeStats(pluginData.stats);
    const stats_element = $(`#${pluginName}-stats`);
    if (stats_element.attr("data-original-title") !== stats) {
        // only update the tooltip if the stats actually changed
        stats_element
            .attr("data-original-title", stats)
            .tooltip('update');
    }
}

function getPluginRuntimeStats(stats) {
    if (stats !== null) {
        return `min: ${stats.min}s
            max: ${stats.max}s
            mean: ${stats.mean}s
            median: ${stats.median}s
            count: ${stats.count}`;
    } else {
        return "N/A<br>count: 0";
    }
}

function updateCurrentAnalyses(analysisData) {
    const currentAnalysesElement = document.getElementById("current-analyses");
    const currentAnalysesHTML = [].concat(
        Object.entries(analysisData.current_analyses)
            .map(([uid, analysisStats]) => createCurrentAnalysisItem(analysisStats, uid)),
        Object.entries(analysisData.recently_finished_analyses)
            .map(([uid, analysisStats]) => createCurrentAnalysisItem(analysisStats, uid, true)),
        Object.entries(analysisData.recently_canceled_analyses)
            .map(([uid, analysisStats]) => createCurrentAnalysisItem(analysisStats, uid, false, true)),
    ).join("\n");
    currentAnalysesElement.innerHTML = currentAnalysesHTML !== "" ? currentAnalysesHTML : "No analysis in progress";
    document.querySelectorAll('div[role=tooltip]').forEach((element) => {
        element.remove();
    });
    $("body").tooltip({selector: '[data-toggle="tooltip"]'});  // update tooltips for dynamically created elements
}

function createCurrentAnalysisItem(data, uid, isFinished = false, isCancelled = false) {
    const timeString = isFinished ? `Finished in ${getDuration(null, data.duration)}` : `${getDuration(data.start_time)}`;
    const total = isFinished ? data.total_files_count : data.total_count;
    const showDetails = Boolean(document.getElementById("ca-show-details").checked);
    const width = isFinished || isCancelled || !showDetails ? "30px" : "50%";
    const unpackingIsFinished = isFinished ? null : (data.unpacked_count == data.total_count);
    const padding = isFinished || isCancelled || !showDetails ? "88%" : "47%";
    const cancelButton = isFinished || isCancelled ? '' : `
        <button type="button" class="close" onclick="cancelAnalysis(this, '${uid}')" style="font-size: 1.1rem; color: red; opacity: 1;">
            <span aria-hidden="true">
                <i class="fas fa-trash-alt" data-toggle="tooltip" data-placement="bottom" title="" data-original-title="Cancel Analysis"></i>
            </span>
        </button>
    `;
    const elapsedTime = isCancelled ? 'Cancelled' : `
        <tr>
            ${createIconCell("clock", "Elapsed Time", width)}
            <td>
                <p class="card-text">${timeString}</p>
            </td>
        </tr>
    `;
    return `
            <div class="card mt-2">
                <h6 class="card-title p-2" style="margin-bottom: 0 !important; padding-bottom: 0 !important;">
                    <a class="clickable" href='/analysis/${uid}/ro/${uid}'>
                        ${data.hid}
                    </a>
                    ${cancelButton}
                </h6>
                <div class="card-body p-2">
                    <table class="table table-borderless table-sm mb-0">
                        ${elapsedTime}
                        <tr>
                            ${createIconCell("box-open", "Unpacking Progress", width)}
                            ${createProgressBarCell(isFinished ? data.total_files_count : data.unpacked_count, total, padding, isFinished, isCancelled)}
                        </tr>
                        <tr>
                            ${createIconCell("microscope", "Analysis Progress", width)}
                            ${createProgressBarCell(isFinished ? data.total_files_count : data.analyzed_count, total, padding, isFinished, isCancelled)}
                        </tr>
                        ${!isFinished && !isCancelled && showDetails ? createPluginProgress(data, unpackingIsFinished) : ""}
                    </table>
                </div>
            </div>
    `;
}

function cancelAnalysis(element, root_uid) {
    element.innerHTML = `
        <div class="spinner-border text-danger" role="status">
            <span class="sr-only">Cancelling...</span>
        </div>
    `;
    fetch(`/ajax/cancel_analysis/${root_uid}`).then(response => {
        if (!response.ok) {
            console.log(`Error: could not cancel analysis of ${root_uid}`);
        }
    });
}

function createPluginProgress(data, unpackingIsFinished) {
    return Object.entries(data.plugins).map(
        ([pluginName, pluginCount]) => createSinglePluginProgress(pluginName, pluginCount, data.total_count_with_duplicates, unpackingIsFinished)
    ).join("\n");
}

function createSinglePluginProgress(plugin, count, total, unpackingIsFinished) {
    return `
        <tr>
            <td class="text-right">${plugin}</td>
            ${createProgressBarCell(count, total, "47%", unpackingIsFinished)}
        </tr>
    `;
}

function createProgressBarCell(count, total, width, unpackingIsFinished = true, isCancelled = false) {
    const progress = count / total * 100;
    const progressString = `${count} / ${total} (${progress.toFixed(1)}%)`;
    const divClass = (progress >= 100.0) ? `progress-bar ${unpackingIsFinished ? "bg-success" : "bg-warning"}` : isCancelled ? "bg-danger" : "progress-bar";
    const pStyle = {
        "color": "white",
        "font-size": "0.75rem",
        "position": "absolute",
        "z-index": "3",
        "width": `${width}`,
        "margin-top": "1px",
        "text-align": "center",
    };
    return `
        <td class="align-middle">
            <p style="${objectToStyle(pStyle)}">${progressString}</p>
            <div class="progress" style="height: 20px;">
                <div class="${divClass}" role="progressbar" style="width: ${progress}%"></div>
            </div>
        </td>
    `;
}

function objectToStyle(obj) {
    return Object.entries(obj).map(([k, v]) => `${k}: ${v};`).join(" ");
}

function createIconCell(icon, tooltip, width) {
    return `
        <td class="align-middle text-right" style="width: ${width};" data-toggle="tooltip" data-placement="bottom" title="${tooltip}">
            <i class="fas fa-${icon}"></i>
        </td>
    `;
}

function getDuration(start = null, duration = null) {
    duration = duration != null ? duration : Date.now() / 1000 - start;
    const date = new Date(duration * 1000);
    if (date.getUTCHours() > 0) {
        return date.toUTCString().slice(-12, -4);  // returns something like '01:23:45'
    } else {
        return date.toUTCString().slice(-9, -4);  // returns something like '23:45'
    }
}
