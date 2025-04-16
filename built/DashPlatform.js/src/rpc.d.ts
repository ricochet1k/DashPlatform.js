import { PlatformClient } from "./generated/platform/v0/platform.client.ts";
import { CoreClient } from "./generated/core/v0/core.client.ts";
import { RpcTransport } from "@protobuf-ts/runtime-rpc";
export declare class NodeConnection {
    readonly transport: RpcTransport;
    readonly core: CoreClient;
    readonly platform: PlatformClient;
    constructor(transport: RpcTransport, core: CoreClient, platform: PlatformClient);
}
export declare function connectToNode(address: string): NodeConnection;
