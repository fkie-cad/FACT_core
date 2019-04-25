function get_extended_tooltip(element, data){
    var value = data.datasets[element.datasetIndex].data[element.index];
    var sum = data.datasets[element.datasetIndex].data.reduce(function(pv, cv) { return pv + cv; }, 0);
    var percent = Math.round((value / sum) * 1000) / 10;
    return value + " (" + percent + "%)";
}

function get_extended_tooltip_value_percentage_pairs(element, data){
    var percent = _round(data.datasets[element.datasetIndex].percentage[element.index], 2);
    var value = data.datasets[element.datasetIndex].data[element.index];
    return value + " (" + percent + " %)";
}

function _round(value, decimals){
    return Number(Math.round(value*100+'e'+decimals)+'e-'+decimals);
}

function _truncate(str){
    if (str.length > 20) {
        return str.substr(0, 17) + '...';
    } else {
        return str;
    }
}

function get_full_title(tooltipItems, data) {
    return data.labels[tooltipItems[0].index];
}

var chart_options = {
    legend: {position: "bottom", display: false},
    tooltips: {
        callbacks: {
            label: get_extended_tooltip,
            title: get_full_title,
        }
    },
    scales: {
        xAxes: [{display: false, ticks: {beginAtZero: true}}],
        yAxes: [{ticks: {callback: _truncate}}],
    }
};

var chart_options_value_percentage_pairs = {
    legend: {position: "bottom", display: false},
    tooltips: {
        callbacks: {
            label: get_extended_tooltip_value_percentage_pairs,
            title: get_full_title,
        }
    },
    scales: {
        xAxes: [{display: false, ticks: {beginAtZero: true}}],
        yAxes: [{ticks: {callback: _truncate}}],
    }
};

function _add(a, b){
    return a + b;
}

function create_horizontal_bar_chart(canvas_id, chart_data, link, value_percentage_present_flag) {
    var ctx = document.getElementById(canvas_id);

    if (value_percentage_present_flag) {
        chart_opt = chart_options_value_percentage_pairs;
        max = chart_data.datasets[0].data.slice(0, 2).reduce(_add);
    } else {
        chart_opt = chart_options;
        max = Math.max(...chart_data.datasets[0].data);
    }
    chart_opt.scales.xAxes[0].ticks.max = max * 1.05;

    var BarChart = new Chart(ctx, {type: "horizontalBar", data: chart_data, options: chart_opt});

    document.getElementById(canvas_id).onclick = function(evt){
        var points = BarChart.getElementsAtEvent(evt);
        var label = BarChart.data.labels[points[0]._index];
        if ((points[0] !== undefined) && (label != "rest"))
            window.location = link.replace("PLACEHOLDER", label);
    };

    return BarChart;
}
