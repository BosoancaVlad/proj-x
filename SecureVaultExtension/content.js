console.log("🕵️‍♂️ Secure Vault Extension is scanning...");
let hasAutofilled = false;

// 🧪 TEMPORARY TEST: Ping the server as soon as the page loads
chrome.runtime.sendMessage({ action: "pingServer" }, (response) => {
    console.log("📡 Server Ping Result:", response);
});

function showToast(message, isError = true, saveAction = null) {
    const toast = document.createElement("div");

    let htmlContent = isError ? `<strong>REFUSED:</strong> ${message}` : `<strong>SAFE:</strong> ${message}`;

    //save button
    if (!isError && saveAction) {
        htmlContent += `<br><button id="vault-save-btn" style="margin-top: 12px; padding: 6px 12px; background: white; color: #28a745; border: none; border-radius: 5px; font-weight: bold; cursor: pointer; width: 100%;">Save to My Vault</button>`;
    }

    toast.innerHTML = htmlContent;
    toast.style.position = "fixed";
    toast.style.top = "20px";
    toast.style.right = "20px";
    toast.style.backgroundColor = isError ? "#dc3545" : "#28a745";
    toast.style.color = "white";
    toast.style.padding = "15px 25px";
    toast.style.borderRadius = "8px";
    toast.style.zIndex = "999999";
    toast.style.boxShadow = "0px 4px 15px rgba(0,0,0,0.3)";
    toast.style.fontFamily = "Arial, sans-serif";
    toast.style.fontSize = "16px";

    document.body.appendChild(toast);

    //make the button clickable
    if (!isError && saveAction) {
        document.getElementById('vault-save-btn').addEventListener('click', () => {
            saveAction();
            toast.innerHTML = `<strong>Successfully Saved to Vault!</strong>`;
            setTimeout(() => toast.remove(), 2500); //disappear after saving
        });
        setTimeout(() => toast.remove(), 10000); //10 seconds to click it
    } else {
        setTimeout(() => toast.remove(), 6000); //normal 6 second disappear
    }
}

setInterval(() => {
    if (hasAutofilled) return;

    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const usernameInputs = document.querySelectorAll('input[type="text"], input[type="email"]');

    if (passwordInputs.length > 0) {
        let passBox = passwordInputs[0];

        if (!passBox.dataset.scanned) {
            passBox.style.border = "3px solid #ffc107";
            passBox.dataset.scanned = "true";

            const currentUrl = window.location.hostname;

            //autofill scanner
            chrome.runtime.sendMessage({ action: "getCredentials", url: currentUrl }, (data) => {
                if (!data || data.error) return;

                if (data.found === true) {
                    passBox.value = data.password;
                    passBox.style.border = "3px solid #28a745";
                    passBox.dispatchEvent(new Event('input', { bubbles: true }));

                    if (usernameInputs.length > 0) {
                        usernameInputs[usernameInputs.length - 1].value = data.username;
                        usernameInputs[usernameInputs.length - 1].style.border = "3px solid #28a745";
                        usernameInputs[usernameInputs.length - 1].dispatchEvent(new Event('input', { bubbles: true }));
                    }
                    hasAutofilled = true;
                    showToast(`Autofilled credentials for ${currentUrl}`, false);
                }
            });

            //security guard
            passBox.addEventListener('blur', () => {
                let typedPassword = passBox.value;

                //grab the username they typed (if it can find the box)
                let typedUsername = "UnknownUser";
                if (usernameInputs.length > 0) {
                    typedUsername = usernameInputs[usernameInputs.length - 1].value;
                }

                if (typedPassword.length > 0 && !hasAutofilled) {
                    passBox.style.border = "3px solid #17a2b8";

                    chrome.runtime.sendMessage({ action: "checkSecurity", url: currentUrl, password: typedPassword }, (data) => {
                        if (!data || data.error) return;

                        if (data.status === "refused") {
                            passBox.style.border = "3px solid #dc3545";
                            showToast(data.reason, true);
                        } else {
                            passBox.style.border = "3px solid #28a745";

                            //pass the save action to the toast!
                            showToast(data.reason, false, () => {
                                chrome.runtime.sendMessage({
                                    action: "saveCredentials",
                                    url: currentUrl,
                                    username: typedUsername,
                                    password: typedPassword
                                });
                            });
                        }
                    });
                }
            });
        }
    }
}, 1000);