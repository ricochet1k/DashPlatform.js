import { GrpcWebFetchTransport } from "@protobuf-ts/grpcweb-transport";
import { PlatformClient } from "./generated/platform/v0/platform.client.js";
import { CoreClient } from "./generated/core/v0/core.client.js";
export class NodeConnection {
    transport;
    core;
    platform;
    constructor(transport, core, platform) {
        this.transport = transport;
        this.core = core;
        this.platform = platform;
    }
}
export function connectToNode(address) {
    const transport = new GrpcWebFetchTransport({
        baseUrl: address,
        // format: 'binary',
    });
    const core = new CoreClient(transport);
    const platform = new PlatformClient(transport);
    return new NodeConnection(transport, core, platform);
}
