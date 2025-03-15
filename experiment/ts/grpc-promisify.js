/**
 * Promise-based wrapper around @grpc/grpc-js API.
 *
 * Original from https://gist.github.com/paskozdilar/196b212a1df66463487fa2b75dde049c
 *
 *
 * USAGE:
 *
 * let client: grpc.Client;
 *
 * // unary
 * let response: ResponseType = await UnaryCall(client, client.unaryMethod, request)
 *
 * // client stream
 * let response = await ClientStream(client, client.clientStreamMethod, async function*() {
 *    yield request1;
 *    yield request2;
 * });
 *
 * // server stream
 * for await (let response of ServerStream(client, client.serverStreamMethod, request)) {
 *    // ...
 * }
 *
 * // bidirectional stream
 * for await (let response of Bidirectional(client, client.bidirectionalMethod, async function*() {
 *    yield request1;
 *    yield request2;
 * }) {
 *    // ...
 * }
 *
 *
 * NOTE:
 *
 * Due to TypeScript's type inference limitations, return values must be
 * explicitly annotated for type inference/checking to work.
 */
export async function UnaryCall(client, method, request, options) {
    return await new Promise((resolve, reject) => {
        const call = method.call(client, request, options ?? {}, (error, response) => {
            if (error !== null) {
                reject(error);
            }
            else {
                resolve(response);
            }
        });
        if (options?.signal) {
            options.signal.addEventListener('abort', () => call.cancel());
        }
    });
}
export async function ClientStream(client, method, requests, signal) {
    return await new Promise(async (resolve, reject) => {
        const stream = method.call(client, (error, response) => {
            if (error !== null) {
                reject(error);
            }
            else {
                resolve(response);
            }
        });
        if (signal !== undefined) {
            signal.addEventListener('abort', () => stream.cancel());
        }
        try {
            for await (const request of requests()) {
                await new Promise((resolve, reject) => {
                    if (!stream.write(request, (error) => {
                        if (error !== undefined) {
                            reject(error);
                        }
                    })) {
                        stream.once('drain', resolve);
                    }
                    else {
                        resolve();
                    }
                });
            }
            stream.end();
        }
        catch (error) {
            reject(error);
        }
    });
}
export async function* ServerStream(client, method, request, signal) {
    const stream = method.call(client, request);
    if (signal !== undefined) {
        signal.addEventListener('abort', () => stream.cancel());
    }
    let resolve;
    let reject;
    let promise = new Promise((_resolve, _reject) => {
        resolve = _resolve;
        reject = _reject;
    });
    let buffer = [];
    let ready = true;
    stream.on('data', (response) => {
        // if not ready, push to buffer
        if (!ready) {
            buffer.push(response);
            return;
        }
        ready = false;
        // otherwise 
        resolve(response);
        promise = new Promise((_resolve, _reject) => {
            resolve = _resolve;
            reject = _reject;
        });
    });
    stream.on('end', () => resolve());
    stream.on('error', (error) => reject(error));
    while (true) {
        // drain buffer
        while (buffer.length > 0) {
            yield buffer.shift();
        }
        // wait for data
        ready = true;
        const response = await promise;
        if (response === undefined) {
            break;
        }
        yield response;
    }
}
export async function* Bidirectional(client, method, requests, signal) {
    const stream = method.call(client);
    if (signal !== undefined) {
        signal.addEventListener('abort', () => stream.cancel());
    }
    const sendDataInBackground = async () => {
        try {
            for await (const request of requests()) {
                await new Promise((resolve, reject) => {
                    const draining = !stream.write(request, (error) => {
                        if (error !== undefined) {
                            reject(error);
                        }
                    });
                    if (draining) {
                        stream.once('drain', resolve);
                    }
                    else {
                        resolve();
                    }
                });
            }
        }
        catch { }
        finally {
            stream.end();
        }
    };
    sendDataInBackground();
    let resolve;
    let reject;
    let promise = new Promise((_resolve, _reject) => {
        resolve = _resolve;
        reject = _reject;
    });
    let buffer = [];
    let ready = true;
    stream.on('data', (response) => {
        // if not ready, push to buffer
        if (!ready) {
            buffer.push(response);
            return;
        }
        ready = false;
        // otherwise 
        resolve(response);
        promise = new Promise((_resolve, _reject) => {
            resolve = _resolve;
            reject = _reject;
        });
    });
    stream.on('end', () => resolve());
    stream.on('error', (error) => reject(error));
    while (true) {
        // drain buffer
        while (buffer.length > 0) {
            yield buffer.shift();
        }
        // wait for data
        ready = true;
        const response = await promise;
        if (response === undefined) {
            break;
        }
        yield response;
    }
}
