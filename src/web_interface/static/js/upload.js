$(function () {
    $('#release_date').datepicker({
        format: 'yyyy-mm-dd',
        todayHighlight: true
    });
});
function add_device_class_options(selected_device_class, selected_vendor, data) {
    $('#device_name').empty();
    if (data.hasOwnProperty(selected_device_class)) {
        if (data[selected_device_class].hasOwnProperty(selected_vendor)) {
            var device_classes = data[selected_device_class][selected_vendor];
            device_classes.sort();
            for (var key in device_classes) {
                if (device_classes.hasOwnProperty(key)) {
                    $('#device_name').append('<option>' + device_classes[key] + '</option>');
                }
            }
        }
    }
    $('#device_name').append('<option>' + 'new entry' + '</option>');
}
function update_text_input(element, this_text_input) {
    if (element.options[element.selectedIndex].value == 'new entry') {
        this_text_input.style.display = 'initial';
        this_text_input.value = '';
    } else {
        this_text_input.style.display = 'none';
        this_text_input.value = element.options[element.selectedIndex].value;
    }
}
function update_device_names() {
    var vendor_dropdown = document.getElementById('vendor');
    var device_class_dropdown = document.getElementById('device_class');
    if ((vendor_dropdown.selectedIndex != -1) && (device_class_dropdown.selectedIndex != -1)) {
        document.getElementById('device_name').disabled = false;
        var selected_device_class = device_class_dropdown.options[device_class_dropdown.selectedIndex].value;
        var selected_vendor = vendor_dropdown.options[vendor_dropdown.selectedIndex].value;
        add_device_class_options(selected_device_class, selected_vendor, device_names);
    }
}
function change_selected_plugins(selected_theme) {
    for (var plugin in plugin_dict) {
        if (plugin_dict.hasOwnProperty(plugin)) {
            plugin_checkbox = document.getElementById(plugin);
            if (plugin_checkbox != null) {
                plugin_in_theme = plugin_dict[plugin][2][selected_theme];
                plugin_checkbox.firstElementChild.firstElementChild.checked = plugin_in_theme;
            }
        }
    }
}
