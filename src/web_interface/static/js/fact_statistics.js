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

function set_links(canvas_id, any_chart, link) {

    document.getElementById(canvas_id).onclick = function(evt){
        var points = any_chart.getElementsAtEvent(evt);
        var label = any_chart.data.labels[points[0]._index];
        if ((points[0] !== undefined) && (label != "rest"))
            window.location = link.replace("PLACEHOLDER", label);
    };

}

function set_links_from_data(canvas_id, chart, link) {

    document.getElementById(canvas_id).onclick = function(evt){
        var points = chart.getElementsAtEvent(evt);
        if (chart.data.datasets[0].links !== undefined) {
            var key = chart.data.datasets[0].links[points[0]._index];
            window.location = link.replace("PLACEHOLDER", key);
        }
    };

}

function create_horizontal_bar_chart(canvas_id, chart_data, link, value_percentage_present_flag = false, links_in_data = false) {
    var ctx = document.getElementById(canvas_id);

    if (value_percentage_present_flag) {
        chart_opt = chart_options_value_percentage_pairs;
        max = chart_data.datasets[0].data.slice(0, 2).reduce(_add);
    } else {
        chart_opt = chart_options;
        max = Math.max(...chart_data.datasets[0].data);
    }
    chart_opt.scales.xAxes[0].ticks.max = max * 1.05;

    var BarChart = new Chart(
        ctx, {
            type: "horizontalBar",
            data: chart_data,
            options: chart_opt
        }
    );

    if (links_in_data) {
        set_links_from_data(canvas_id, BarChart, link);
    } else {
        set_links(canvas_id, BarChart, link);
    }

    return BarChart;
}

function create_pie_chart(canvas_id, chart_data, link) {
    var ctx = document.getElementById(canvas_id);

    var PieChart = new Chart(
        ctx, {
            type: "doughnut",
            data: chart_data,
            options: {
                legend: {
                    fullWidth: false,
                    position: 'right',
                    labels: {
                        boxWidth: 20,
                        fontSize: 10
                    }
            }
        }
        }
    );

    set_links(canvas_id, PieChart, link);

    return PieChart;
}

