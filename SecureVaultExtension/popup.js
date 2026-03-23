document.addEventListener('DOMContentLoaded', () => {
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');

    //ping the Python Server
    chrome.runtime.sendMessage({ action: "pingServer" }, (response) => {

        // If we get a response and the message is "hello"
        if (response && response.message === "hello") {
            statusDot.className = "dot online";
            statusText.innerText = "Server Connected";
            statusText.style.color = "#28a745";
        } else {
            // If the server is offline or crashed
            statusDot.className = "dot offline";
            statusText.innerText = "Server Offline";
            statusText.style.color = "#dc3545";
        }
    });
});