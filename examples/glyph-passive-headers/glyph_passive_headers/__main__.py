import asyncio
import logging
import argparse
import os

import grpc
from glyph_plugin_runtime.glyph import common_pb2, plugin_bus_pb2, plugin_bus_pb2_grpc

# --- Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# --- gRPC Communication ---

async def generate_requests(send_queue: asyncio.Queue, auth_token: str):
    """Generates requests to send to the server, starting with authentication."""
    # First, send the PluginHello message
    hello = plugin_bus_pb2.PluginHello(
        auth_token=auth_token,
        plugin_name="glyph-passive-headers",
        pid=os.getpid(),
        subscriptions=["FLOW_RESPONSE"],
        capabilities=["CAP_EMIT_FINDINGS"],
    )
    yield plugin_bus_pb2.PluginEvent(hello=hello)
    logger.info(f"Sent PluginHello authentication request for pid {hello.pid}.")

    # Then, listen for findings to send from the queue
    while True:
        finding = await send_queue.get()
        yield plugin_bus_pb2.PluginEvent(finding=finding)
        logger.info(f"Sent finding of type: {finding.type}")


async def run_event_stream(stub, send_queue: asyncio.Queue, auth_token: str):
    """Manages the bidirectional event stream with the gRPC server."""
    logger.info("Starting event stream...")
    try:
        request_iterator = generate_requests(send_queue, auth_token)
        async for event in stub.EventStream(request_iterator):
            logger.info(f"Received host event from core version: {event.core_version}")
            if event.HasField("flow_event"):
                flow_event = event.flow_event
                if flow_event.type == common_pb2.FlowEvent.FLOW_RESPONSE:
                    logger.info("Received a FLOW_RESPONSE event.")
                    # This is where the plugin's logic goes.
                    # We'll check for a "missing security header".
                    finding = create_security_header_finding()
                    await send_queue.put(finding)
    except grpc.aio.AioRpcError as e:
        logger.error(f"gRPC Error: [{e.code()}] {e.details()}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)


def create_security_header_finding():
    """Creates a sample 'Finding' for a missing security header."""
    return common_pb2.Finding(
        type="missing-security-header",
        message="The response is missing the 'X-Content-Type-Options' header.",
        severity=common_pb2.Severity.MEDIUM,
        metadata={
            "checked_header": "X-Content-Type-Options",
            "recommended_value": "nosniff",
        },
    )


async def main_async(server_address: str, auth_token: str):
    """The main async function that sets up and runs the plugin."""
    send_queue = asyncio.Queue()
    logger.info(f"Connecting to gRPC server at {server_address}")
    async with grpc.aio.insecure_channel(server_address) as channel:
        stub = plugin_bus_pb2_grpc.PluginBusStub(channel)
        await run_event_stream(stub, send_queue, auth_token)


def main():
    """Defines the command-line interface and runs the plugin."""
    parser = argparse.ArgumentParser(description="Glyph Passive Headers Plugin")
    parser.add_argument(
        "-s", "--server", default="localhost:50051", help="gRPC server address"
    )
    parser.add_argument(
        "-t", "--token", default="supersecrettoken", help="Authentication token"
    )
    args = parser.parse_args()

    try:
        asyncio.run(main_async(args.server, args.token))
    except KeyboardInterrupt:
        logger.info("Plugin shutting down.")


if __name__ == "__main__":
    main()
