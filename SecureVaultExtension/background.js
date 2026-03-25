chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

    //first action: get saved credentials (Autofill)
    if (request.action === "getCredentials") {
        fetch("https://secure-vault-h0a6.onrender.com/api/get_credentials", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url })
        }).then(r => r.json()).then(d => sendResponse(d)).catch(e => sendResponse({ error: "Failed" }));
        return true;
    }

    //second action: check a newly typed password (Security Guard)
    if (request.action === "checkSecurity") {
        fetch("https://secure-vault-h0a6.onrender.com/api/password/check", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url, password: request.password })
        }).then(r => r.json()).then(d => sendResponse(d)).catch(e => sendResponse({ error: "Failed" }));
        return true;
    }

    //third action: save new credentials
    if (request.action === "saveCredentials") {
        fetch("https://secure-vault-h0a6.onrender.com/api/save_credentials", {
            method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: request.url, username: request.username, password: request.password })
        }).then(r => r.json()).then(d => sendResponse(d)).catch(e => sendResponse({ error: "Failed" }));
        return true;
    }

    //fourth action: check if the server is alive   
    if (request.action === "pingServer") {
        fetch("https://secure-vault-h0a6.onrender.com/info") //no POST or body needed for a GET request
            .then(response => response.json())
            .then(data => sendResponse(data))
            .catch(error => sendResponse({ error: "Server is offline" }));
        return true;
    }
});