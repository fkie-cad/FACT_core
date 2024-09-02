$(() => {
    $('#release_date').datepicker({
        format: 'yyyy-mm-dd',
        todayHighlight: true
    });
});

function add_device_class_options(selected_device_class, selected_vendor, data) {
    const deviceClassButton = document.getElementById("device_class_select_button");
    let deviceNameList = $('#device_name_list');
    deviceNameList.empty();
    if (data.hasOwnProperty(selected_device_class)) {
        if (data[selected_device_class].hasOwnProperty(selected_vendor)) {
            let device_classes = data[selected_device_class][selected_vendor];
            // remove duplicates
            device_classes = [...new Set(device_classes)];
            device_classes.sort();
            if (device_classes.length > 0) {
                for (let index in device_classes) {
                    deviceNameList.append(`
                        <a class="dropdown-item" href="#" onClick="updateInput('device_name', this)">
                            ${device_classes[index]}
                        </a>
                    `);
                }
                deviceClassButton.disabled = false;
                return;
            }
        }
    }
    deviceClassButton.disabled = true;
}

function update_device_names() {
    const deviceClassInput = document.getElementById("device_class");
    const vendorInput = document.getElementById("vendor");
    const vendor = vendorInput.value.trim();
    const device_class = deviceClassInput.value.trim();
    if (vendor.length > 0 && device_class.length > 0) {
        add_device_class_options(device_class, vendor, device_names);
    }
}

function change_selected_plugins(preset_name) {
    for (const [plugin_name, plugin_data] of Object.entries(plugin_dict)) {
        const plugin_checkbox = document.getElementById(plugin_name);
        if (plugin_checkbox != null) {
            // plugin_data is a tuple, and the third element is the dict containing preset info
            let [_, __, preset] = plugin_data;
            plugin_checkbox.firstElementChild.firstElementChild.checked = preset[preset_name];
        }
    }
}

function updateInput(input_id, element, do_update = false) {
    const input = document.getElementById(input_id);
    input.value = element.innerText;
    if (do_update) {
        update_device_names();
    }
}

function filterFunction(input) {
    let filter = input.value.toLowerCase();
    input.parentElement.querySelectorAll(".dropdown-item").forEach(element => {
        if (!element.innerText.toLowerCase().includes(filter)) {
            element.style.display = "none";
        } else {
            element.style.display = "";
        }
    });
}
