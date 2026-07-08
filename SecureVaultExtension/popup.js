document.addEventListener("DOMContentLoaded", () => {
    const loginSection = document.getElementById("login-section");
    const unlockSection = document.getElementById("unlock-section");
    const statusSection = document.getElementById("status-section");
    const statusText = document.getElementById("status-text");
    const statusDot = document.getElementById("status-dot");

    //Ask the background script what our current state is
    chrome.runtime.sendMessage({ action: "pingServer" }, (response) => {
        if (response && response.error) {
            //server is offline - show it instead of the login form
            statusSection.style.display = "flex";
            statusDot.className = "dot offline";
            statusText.innerText = "Secure Vault is Offline";
            statusText.style.color = "#dc3545";
        } else if (response && response.status === "logged_in") {
            // We are logged into the server -> Now check if the extension is UNLOCKED
            chrome.runtime.sendMessage({ action: "checkLockStatus" }, (lockResponse) => {
                if (lockResponse.isUnlocked) {
                    showActiveStatus();
                } else {
                    unlockSection.style.display = "block"; // Show the new Unlock box
                }
            });
        } else {
            // We are totally logged out
            loginSection.style.display = "block";
        }
    });

    // The new Log In Button
    document.getElementById("login-btn").addEventListener("click", () => {
        const user = document.getElementById("ext-username").value;
        const pass = document.getElementById("ext-password").value;

        chrome.runtime.sendMessage({ action: "extensionLogin", username: user, password: pass }, (response) => {
            if (response && response.status === "success") {
                // Instantly unlock the vault since they just typed the password!
                chrome.runtime.sendMessage({ action: "unlockVault", masterPassword: pass }, () => {
                    loginSection.style.display = "none";
                    showActiveStatus();
                });
            } else {
                document.getElementById("error-msg").style.display = "block";
            }
        });
    });

    // The new Unlock Button (For when they are logged in, but memory wiped)
    document.getElementById("unlock-btn").addEventListener("click", () => {
        const pass = document.getElementById("unlock-password").value;
        chrome.runtime.sendMessage({ action: "unlockVault", masterPassword: pass }, (response) => {
            if (response.success) {
                unlockSection.style.display = "none";
                showActiveStatus();
            }
        });
    });

    function showActiveStatus() {
        statusSection.style.display = "flex";
        statusDot.className = "dot online";
        statusText.innerText = "Vault Unlocked & Scanning";
        statusText.style.color = "#28a745";
    }
});
