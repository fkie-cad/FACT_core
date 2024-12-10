const lightTextColor = "#212529";
const darkTextColor = "#ccc";
const lightLineColor = "#f8f9fa";
const darkLineColor = "#343a40";

function toggleDarkMode() {
    let isDark = document.body.classList.toggle('dark-mode');
    localStorage.setItem('darkMode', isDark ? 'enabled' : 'disabled');
}
document.addEventListener('DOMContentLoaded', (event) => {
    let isDark = (localStorage.getItem('darkMode') || 'disabled') === 'enabled';
    document.getElementById("darkModeSwitch").checked = isDark;
    if (isDark) {
        toggleDarkMode();
    }
});

function getTextColor() {
    return isDark() ? darkTextColor : lightTextColor;
}

function getLineColor() {
    return isDark() ? darkLineColor : lightLineColor;
}

function isDark() {
    return (
        document.getElementById("darkModeSwitch").checked ||
        localStorage.getItem('darkMode') === 'enabled'
    );
}