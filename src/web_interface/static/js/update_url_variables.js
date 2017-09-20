function update_url_variables(url, variable, value) {
    var start = url.indexOf("?");
    if (start !== -1) {
        var parameter_string = url.slice(start + 1);
        url = url.slice(0, start);
        var parameters = parameter_string.split("&");
        var parameters_dict = {};
        for (var i = 0; i < parameters.length; i++) {
            [key, value_] = parameters[i].split("=");
            parameters_dict[key] = value_;
        }
        if (value) {
            parameters_dict[variable] = value;
        } else {
            delete parameters_dict[variable];
        }
        if (Object.keys(parameters_dict).length > 0) {
            parameters = [];
            for (var key in parameters_dict) {
                parameters.push([key, parameters_dict[key]].join("="));
            }
            parameter_string = "?" + parameters.join("&");
        } else {
            parameter_string = "";
        }
    } else if (value) {
        parameter_string = "?" + [variable, value].join("=");
    } else {
        parameter_string = "";
    }
    return url + parameter_string
}
