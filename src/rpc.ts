import { GrpcWebFetchTransport } from "@protobuf-ts/grpcweb-transport"
import { PlatformClient } from "./generated/platform/v0/platform.client.ts"
import { CoreClient } from "./generated/core/v0/core.client.ts"
import { RpcTransport } from "@protobuf-ts/runtime-rpc"

export class NodeConnection {
    constructor(
        public readonly transport: RpcTransport,
        public readonly core: CoreClient,
        public readonly platform: PlatformClient,
    ){}
}

export function connectToNode(address: string) {
    const transport = new GrpcWebFetchTransport({
        baseUrl: address,
        // format: 'binary',
    })
    const core = new CoreClient(transport)
    const platform = new PlatformClient(transport)

    return new NodeConnection(transport, core, platform);
}
