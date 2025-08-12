import asyncio

import uvicorn

import bytedance.jeddak_secure_channel as jsc
from bytedance.jeddak_trusted_mcp import TrustedMcp

jsc_config = jsc.ServerConfig.from_file("server_config.json")
weather_mcp = TrustedMcp(name="Weather service", jsc_config=jsc_config)


@weather_mcp.tool()
def get_weather(city: str) -> dict:
    """Get current weather for a city (e.g. "beijing")."""
    import httpx

    return (
        httpx.get(f"https://wttr.in/{city}?format=j1")
        .json()
        .get("current_condition")[0]
    )


async def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    uvicorn_config = uvicorn.Config(
        weather_mcp.streamable_http_app(), host=args.host, port=args.port
    )
    server = uvicorn.Server(uvicorn_config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())
