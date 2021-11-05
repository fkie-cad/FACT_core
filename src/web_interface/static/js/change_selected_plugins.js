function change_selected_plugins(selected_theme) {
    for (var plugin in plugin_dict) {
        if (plugin_dict.hasOwnProperty(plugin)) {
            plugin_checkbox = document.getElementById(plugin);
            if (plugin_checkbox != null) {
                if (plugin_dict[plugin][2][selected_theme] == true) {
                    plugin_checkbox.firstElementChild.firstElementChild.checked = true;
                } else {
                    plugin_checkbox.firstElementChild.firstElementChild.checked = false;
                }
            }
        }
    }
}