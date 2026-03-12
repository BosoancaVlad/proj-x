chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

    //first action: get saved credentials (Autofill)
    if (request.action === "getCredentials") {
        fetch("http://127.0.0.1:5000/api/get_credentials", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url })
        }).then(r => r.json()).then(d => sendResponse(d)).catch(e => sendResponse({ error: "Failed" }));
        return true;
    }

    //second action: check a newly typed password (Security Guard)
    if (request.action === "checkSecurity") {
        fetch("http://127.0.0.1:5000/api/check_security", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url, password: request.password })
        }).then(r => r.json()).then(d => sendResponse(d)).catch(e => sendResponse({ error: "Failed" }));
        return true;
    }

    //third action: save new credentials
    if (request.action === "saveCredentials") {
        fetch("http://127.0.0.1:5000/api/save_credentials", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url, username: request.username, password: request.password })
        }).then(r => r.json()).then(d => sendResponse(d)).catch(e => sendResponse({ error: "Failed" }));
        return true;
    }
});