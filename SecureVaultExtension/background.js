let sessionMasterPassword = null;
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

    //get saved credentials (Autofill)
    if (request.action === "getCredentials") {
        fetch("http://127.0.0.1:5000/api/get_credentials", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url, master_password: sessionMasterPassword })
        }).then(r => r.json()).then(d => sendResponse(d)).catch(e => sendResponse({ error: "Failed" }));
        return true;
    }
    //check a newly typed password (Security Guard)
    if (request.action === "checkSecurity") {
        fetch("http://127.0.0.1:5000/api/password/check", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url, password: request.password })
        }).then(r => r.json()).then(d => sendResponse(d)).catch(e => sendResponse({ error: "Failed" }));
        return true;
    }

    //save new credentials
    if (request.action === "saveCredentials") {
        fetch("http://127.0.0.1:5000/api/save_credentials", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url, username: request.username, password: request.password })
        }).then(r => r.json()).then(d => sendResponse(d)).catch(e => sendResponse({ error: "Failed" }));
        return true;
    }

    //check if the server is alive   
    if (request.action === "pingServer") {
        fetch("http://127.0.0.1:5000/info", {
            credentials: "include" //check for the session cookie
        })
            .then(response => response.json())
            .then(data => sendResponse(data))
            .catch(error => sendResponse({ error: "Server is offline" }));
        return true;
    }

    //extension login
    if (request.action === "extensionLogin") {
        fetch("http://127.0.0.1:5000/api/login", {
            method: "POST", headers: { "Content-Type": "application/json" },
            credentials: "include", //ID badge to stay logged in
            body: JSON.stringify({ username: request.username, password: request.password })
        }).then(r => r.json()).then(d => sendResponse(d)).catch(e => sendResponse({ error: "Failed" }));
        return true;
    }

    // Check if the extension memory has the password
    if (request.action === "checkLockStatus") {
        sendResponse({ isUnlocked: sessionMasterPassword !== null });
        return true;
    }

    // Save the password into the extension's temporary memory
    if (request.action === "unlockVault") {
        sessionMasterPassword = request.masterPassword;
        // Wake up the content.js scanner
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
            if (tabs[0]) chrome.tabs.sendMessage(tabs[0].id, { action: "wakeUpScanner" });
        });
        sendResponse({ success: true });
        return true;
    }
});