function getExtendedTooltip(element, data) {
    const value = data.datasets[element.datasetIndex].data[element.index];
    const sum = data.datasets[element.datasetIndex].data.reduce((pv, cv) => pv + cv, 0);
    const percent = Math.round((value / sum) * 1000) / 10;
    return `${value} (${percent}%)`;
}

function getExtendedTooltipValuePercentagePairs(element, data) {
    const percent = _round(data.datasets[element.datasetIndex].percentage[element.index], 2);
    const value = data.datasets[element.datasetIndex].data[element.index];
    return `${value} (${percent}%)`;
}

function _round(value, decimals) {
    return Number(Math.round(value * 100 + 'e' + decimals) + 'e-' + decimals);
}

function _truncate(str) {
    if (str.length > 20) {
        return str.slice(0, 17) + '...';
    } else {
        return str;
    }
}

function getFullTitle(tooltipItems, data) {
    return data.labels[tooltipItems[0].index];
}

let chartOptions = {
    legend: {position: "bottom", display: false},
    tooltips: {
        callbacks: {
            label: getExtendedTooltip,
            title: getFullTitle,
        }
    },
    scales: {
        xAxes: [{display: false, ticks: {beginAtZero: true}}],
        yAxes: [{ticks: {callback: _truncate}}],
    }
};

let chartOptionsValuePercentagePairs = {
    ...chartOptions,
    tooltips: {
        callbacks: {
            label: getExtendedTooltipValuePercentagePairs,
            title: getFullTitle,
        }
    },
};

function _add(a, b) {
    return a + b;
}

function setLinks(canvasId, chart, link) {
    document.getElementById(canvasId).onclick = (evt) => {
        const points = chart.getElementsAtEvent(evt);
        const label = chart.data.labels[points[0]._index];
        if ((points[0] !== undefined) && (label !== "rest"))
            window.location = link.replace("PLACEHOLDER", label);
    };
}

function setLinksFromData(canvasId, chart, link) {
    document.getElementById(canvasId).onclick = (evt) => {
        const points = chart.getElementsAtEvent(evt);
        if (chart.data.datasets[0].links !== undefined) {
            const key = chart.data.datasets[0].links[points[0]._index];
            window.location = link.replace("PLACEHOLDER", key);
        }
    };
}

let charts = {};

function createHorizontalBarChart(canvasId, chartData, link, isPercentage = false, linksInData = false) {
    let options, max;

    if (isPercentage) {
        options = chartOptionsValuePercentagePairs;
        max = chartData.datasets[0].data.slice(0, 2).reduce(_add);
    } else {
        options = chartOptions;
        max = Math.max(...chartData.datasets[0].data);
    }
    options.scales.xAxes[0].ticks.max = max * 1.05;

    let BarChart = new Chart(
        document.getElementById(canvasId),
        {
            type: "horizontalBar",
            data: chartData,
            options: options
        }
    );

    if (linksInData) {
        setLinksFromData(canvasId, BarChart, link);
    } else {
        setLinks(canvasId, BarChart, link);
    }
    BarChart.options.scales.yAxes[0].ticks.fontColor = getTextColor();
    charts[canvasId] = BarChart;
    return BarChart;
}

function createPieChart(canvasId, chartData, link) {
    chartData.datasets[0].borderColor = getLineColor();
    chartData.datasets[0].borderWidth = 3;
    let PieChart = new Chart(
        document.getElementById(canvasId),
        {
            type: "doughnut",
            data: chartData,
            options: {
                legend: {
                    fullWidth: false,
                    position: 'right',
                    labels: {
                        boxWidth: 20,
                        fontSize: 10,
                        fontColor: getTextColor(),
                    },
                },
            },
        },
    );
    setLinks(canvasId, PieChart, link);
    charts[canvasId] = PieChart;
    return PieChart;
}

function createHistogram(canvasId, chartData) {
    console.log(`isDark: ${isDark()}`);  // TODO FIXME
    let options = {
        legend: {display: false},
        scales: {
            xAxes: [{ticks: {fontColor: getTextColor()}}],
            yAxes: [
                {
                    ticks: {
                        beginAtZero: true,
                        fontColor: getTextColor(),
                    },
                    scaleLabel: {
                        display: true,
                        labelString: "Firmware Releases",
                        fontColor: getTextColor(),
                    },
                },
            ],
        },
    };
    let dateBarChart = new Chart(
        document.getElementById(canvasId),
        {
            type: "bar",
            data: chartData,
            options: options,
        }
    );
    charts[canvasId] = dateBarChart;
    return dateBarChart;
}

function updateChartColors() {
    Object.entries(charts).forEach(([id, chart]) => {
        try {
            if (chart.config.type === "doughnut") {
                chart.options.legend.labels.fontColor = getTextColor();
                chart.data.datasets[0].borderColor = getLineColor();
            } else if (chart.config.type === "horizontalBar") {
                chart.options.scales.yAxes[0].ticks.fontColor = getTextColor();
            } else if (chart.config.type === "bar") {
                chart.options.scales.yAxes[0].ticks.fontColor = getTextColor();
                chart.options.scales.yAxes[0].scaleLabel.fontColor = getTextColor();
                chart.options.scales.xAxes[0].ticks.fontColor = getTextColor();
            } else {
                console.log(`Error: unknown chart type ${chart.config.type}!`);
            }
            chart.update();
        } catch (e) {
            console.log(`Error when changing lightness of ${id} chart: ${e}`);
        }
    });
}

$(document).ready(function () {
    document.getElementById("darkModeSwitch").addEventListener("change", updateChartColors);
});
