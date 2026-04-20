document.addEventListener('DOMContentLoaded', () => {
    const loginSection = document.getElementById('login-section');
    const statusSection = document.getElementById('status-section');
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');
    const errorMsg = document.getElementById('error-msg');

    //immediately ping the server when the popup opens
    function checkAuthStatus() {
        chrome.runtime.sendMessage({ action: "pingServer" }, (response) => {
            if (response && response.status === "logged_in") {
                //User is logged in ->Show the green dot and their name
                loginSection.style.display = "none";
                statusSection.style.display = "flex";
                statusDot.className = "dot online";
                statusText.innerText = "Vault Unlocked: " + response.username;
                statusText.style.color = "#28a745";
            } else if (response && response.status === "logged_out") {
                //Server is awake, but user needs to log in -> Show form
                statusSection.style.display = "none";
                loginSection.style.display = "block";
            } else {
                //Server is completely turned off
                loginSection.style.display = "none";
                statusSection.style.display = "flex";
                statusDot.className = "dot offline";
                statusText.innerText = "Server Offline";
                statusText.style.color = "#dc3545";
            }
        });
    }

    checkAuthStatus(); // Run it on load

    //Handle the Login Button click
    document.getElementById('login-btn').addEventListener('click', () => {
        const uName = document.getElementById('ext-username').value;
        const pWord = document.getElementById('ext-password').value;

        chrome.runtime.sendMessage({ action: "extensionLogin", username: uName, password: pWord }, (response) => {
            if (response && response.status === "success") {// if the user typed in their password and now the extension works
                errorMsg.style.display = "none";
                checkAuthStatus();// Updates the popup to the green dot

                //Send the wake-up call to the current webpage
                chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
                    if (tabs.length > 0) {
                        chrome.tabs.sendMessage(tabs[0].id, { action: "wakeUpScanner" });
                    }
                });
            } else {
                errorMsg.style.display = "block";//for the invalid credentials message 
            }
        });
    });
});