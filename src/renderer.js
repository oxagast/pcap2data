/**
 * This file will automatically be loaded by webpack and run in the "renderer" context.
 * To learn more about the differences between the "main" and the "renderer" context in
 * Electron, visit:
 *
 * https://electronjs.org/docs/tutorial/process-model
 *
 * By default, Node.js integration in this file is disabled. When enabling Node.js integration
 * in a renderer process, please be aware of potential security implications. You can read
 * more about security risks here:
 *
 * https://electronjs.org/docs/tutorial/security
 *
 * To enable Node.js integration in this file, open up `main.js` and enable the `nodeIntegration`
 * flag:
 *
 * ```
 *  // Create the browser window.
 *  mainWindow = new BrowserWindow({
 *    width: 800,
 *    height: 600,
 *    webPreferences: {
 *      nodeIntegration: true
 *    }
 *  });
 * ```
 */

import './assets/css/style.css';

window.addEventListener("error", (event) => {
    const message = event?.error?.stack || event?.message || "Unknown renderer error";
    console.error("Renderer startup error:", message);
});

window.addEventListener("unhandledrejection", (event) => {
    const reason = event?.reason;
    const message =
        reason && typeof reason === "object" && "stack" in reason
            ? reason.stack
            : String(reason);
    console.error("Unhandled promise rejection in renderer:", message);
});

async function bootstrapRenderer() {
    try {
        await import('./front.js');
    } catch (error) {
        console.error("Failed to bootstrap renderer frontend:", error);
    }
}

void bootstrapRenderer();
