// Builds the Goodies panel content in a worker to keep renderer updates responsive.

// in the worker we need to just test if our input is a goodie, and if so return the goodie data, otherwise null
self.onmessage = async function (event) {
    const { input, goodies } = event.data;
    const lowerInput = input.toLowerCase();
    const goodie = goodies.find((g) => g.toLowerCase() === lowerInput);
    if (goodie) {
        self.postMessage({ goodie });
    } else {
        self.postMessage({ goodie: null });
    }
}