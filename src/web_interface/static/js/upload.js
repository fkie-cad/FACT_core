$(() => {
    $('#release_date').datepicker({
        format: 'yyyy-mm-dd',
        todayHighlight: true
    });
});

function addDeviceNameOptions(selected_device_class, selected_vendor) {
    const dropdownButton = document.getElementById("device_name-button");
    if (allDeviceNames.hasOwnProperty(selected_device_class)) {
        if (allDeviceNames[selected_device_class].hasOwnProperty(selected_vendor)) {
            // update the global variable but without overwriting it
            deviceNames.length = 0; // empty existing array
            deviceNames.push(...new Set(allDeviceNames[selected_device_class][selected_vendor]));  // remove duplicates
            if (deviceNames.length > 0) {
                deviceNames.sort();
                dropdownButton.disabled = false;
                return;
            }
        }
    }
    dropdownButton.disabled = true;
}

function updateDeviceNames() {
    const deviceClassInput = document.getElementById("device_class");
    const vendorInput = document.getElementById("vendor");
    const vendor = vendorInput.value.trim();
    const device_class = deviceClassInput.value.trim();
    if (vendor.length > 0 && device_class.length > 0) {
        addDeviceNameOptions(device_class, vendor);
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

function autocompleteInput(inputId, options) {
    const input = document.getElementById(inputId);
    const dropdownButton = document.getElementById(`${inputId}-button`);
    let currentFocus;

    input.addEventListener("input", populateAutocomplete);
    dropdownButton.addEventListener("click", (event) => {
        let autoComplete = getAutocompleteElement(event.target.parentNode.parentNode);
        if (autoComplete) {
            // clicked on a dropdown button but a menu already exists => close the menu
            closeAll();
        } else {
            input.value = "";
            populateAutocomplete();
        }
    });

    input.addEventListener("keydown", (event) => {
        if (event.ctrlKey && event.code === "Space") {
            populateAutocomplete();
            return;
        } else if (event.code === "Tab") {
            closeAll();
            return;
        }
        let list = document.getElementById(input.id + "-autocomplete-list");
        if (!list) return;
        let listElements = list.getElementsByTagName("li");
        if (event.code === "ArrowDown") {
            currentFocus++;
            setActive(listElements);
        } else if (event.code === "ArrowUp") {
            currentFocus--;
            setActive(listElements);
        } else if (event.code === "Enter") {
            event.preventDefault();  // prevent the form from being submitted
            if (currentFocus > -1) {
                listElements[currentFocus].click();  // simulate a click on the item
            }
        }
    });

    function populateAutocomplete() {
        closeAll();
        currentFocus = -1;
        const list = document.createElement("ul");
        list.setAttribute("id", input.id + "-autocomplete-list");
        list.setAttribute("class", "autocomplete-items list-group border");
        input.parentNode.appendChild(list);

        let listItem;
        options.forEach(option => {
            let index = option.toLowerCase().indexOf(input.value.toLowerCase());
            if (!input.value || index !== -1) {
                listItem = document.createElement("li");
                listItem.setAttribute("class", "list-group-item list-group-item-action");
                listItem.innerHTML = (
                    option.slice(0, index) +
                    // display the matched part in bold (with the class click-through, the event.target in the
                    // eventListener below will not be the <strong/> element)
                    `<strong class="click-through">${option.slice(index, index + input.value.length)}</strong>` +
                    option.slice(index + input.value.length)
                );
                listItem.__value = option;
                listItem.__inputId = inputId;
                listItem.addEventListener("click", (event) => {
                    input.value = event.target.__value;
                    closeAll();
                    if (["device_class", "vendor"].includes(event.target.__inputId)) {
                        updateDeviceNames();
                    }
                });
                list.appendChild(listItem);
            }
        });
    }

    function setActive(elements) {
        if (elements === null || elements.length === 0) return false;
        Array.from(elements).forEach(element => {
            element.classList.remove("active");
        });
        if (currentFocus >= elements.length) {
            currentFocus = 0;
        } else if (currentFocus < 0) {
            currentFocus = (elements.length - 1);
        }
        const selectedElement = elements[currentFocus];
        if (selectedElement) {
            selectedElement.classList.add("active");
            // scroll to the element above the selected one
            selectedElement.parentNode.scroll(
                0, Math.max(0, selectedElement.offsetTop - selectedElement.clientHeight)
            );
        }
    }
}

function closeAll(currentElement) {
    if (currentElement && currentElement.id.endsWith("-button")) {
        // if we clicked on the dropdown button we don't want to close the autocomplete list (we just opened)
        currentElement = getAutocompleteElement(currentElement.parentNode.parentNode);
    } else if (currentElement && currentElement.tagName.toLowerCase() === "input") {
        // also don't close the autocomplete that belongs to an input we just clicked
        currentElement = getAutocompleteElement(currentElement.parentNode);
    }
    const elements = document.getElementsByClassName("autocomplete-items");
    Array.from(elements).forEach((element) => {
        if (currentElement !== element) {
            element.parentNode.removeChild(element);
        }
    });
}

function getAutocompleteElement(parentElement) {
    const autocompletes = parentElement.querySelectorAll("ul");
    if (autocompletes.length === 1) return autocompletes[0];
    return null;
}

document.addEventListener("click", (event) => {
    closeAll(event.target);
});