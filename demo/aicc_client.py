# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

import asyncio
import json
import logging
import os

import httpx
import mcp

from bytedance.jeddak_trusted_mcp import trusted_mcp_client

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

MCP_URL = os.environ.get("MCP_URL", "**")

LLM_BASE_URL = os.environ.get(
    "LLM_BASE_URL", ""
)
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_MODEL_NAME = os.environ.get("LLM_MODEL_NAME", "**")


def format_tool_for_llm(tool: mcp.Tool) -> str:
    """Format tool information for LLM.

    Returns:
        A formatted string describing the tool.
    """
    args_desc = []
    if "properties" in tool.inputSchema:
        for param_name, param_info in tool.inputSchema["properties"].items():
            arg_desc = (
                f"- {param_name}: {param_info.get('description', 'No description')}"
            )
            if param_name in tool.inputSchema.get("required", []):
                arg_desc += " (required)"
            args_desc.append(arg_desc)

    # Build the formatted output with title as a separate field
    output = f"Tool: {tool.name}\n"

    # Add human-readable title if available
    if tool.title:
        output += f"User-readable title: {tool.title}\n"

    output += f"""Description: {tool.description}
Arguments:
{chr(10).join(args_desc)}
"""

    return output


def get_llm_response(messages: list[dict[str, str]]) -> str:
    """Get a response from the LLM."""
    url = LLM_BASE_URL + "/chat/completions"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LLM_API_KEY}",
    }
    payload = {
        "messages": messages,
        "model": LLM_MODEL_NAME,
        "stream": False,
    }

    try:
        with httpx.Client() as client:
            response = client.post(url, headers=headers, json=payload, timeout=5 * 60)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

    except httpx.RequestError as e:
        error_message = f"Error getting LLM response: {str(e)}"
        logging.error(error_message)

        if isinstance(e, httpx.HTTPStatusError):
            status_code = e.response.status_code
            logging.error(f"Status code: {status_code}")
            logging.error(f"Response details: {e.response.text}")

        return f"I encountered an error: {error_message}. Please try again or rephrase your request."


async def process_llm_response(
    llm_response: str, mcp_session: mcp.ClientSession
) -> str | None:
    """Process the LLM response and execute tools if needed."""
    try:
        tool_call = json.loads(llm_response)
    except json.JSONDecodeError:
        return

    if not ("tool" in tool_call and "arguments" in tool_call):
        return

    logging.info(f"Executing tool: {tool_call['tool']}")
    logging.info(f"With arguments: {tool_call['arguments']}")

    tools = (await mcp_session.list_tools()).tools
    if not any(tool.name == tool_call["tool"] for tool in tools):
        return f"Unrecognized tool: {tool_call['tool']}"

    try:
        result = await mcp_session.call_tool(tool_call["tool"], tool_call["arguments"])

        return f"Tool execution result: {result}"
    except Exception as e:
        error_msg = f"Error executing tool: {str(e)}"
        logging.error(error_msg)
        return error_msg


async def run_chatbot(mcp_session: mcp.ClientSession) -> None:
    """Main chat session handler."""
    tools = (await mcp_session.list_tools()).tools

    tools_description = "\n".join(format_tool_for_llm(tool) for tool in tools)

    system_message = (
        "You are a helpful assistant with access to these tools:\n\n"
        f"{tools_description}\n"
        "Choose the appropriate tool based on the user's question. "
        "If no tool is needed, reply directly.\n\n"
        "IMPORTANT: When you need to use a tool, you must ONLY respond with "
        "the exact JSON object format below, nothing else:\n"
        "{\n"
        '    "tool": "tool-name",\n'
        '    "arguments": {\n'
        '        "argument-name": "value"\n'
        "    }\n"
        "}\n\n"
        "After receiving a tool's result:\n"
        "1. Transform the raw data into a natural, conversational response\n"
        "2. Keep responses concise but informative\n"
        "3. Focus on the most relevant information\n"
        "4. Use appropriate context from the user's question\n"
        "5. Avoid simply repeating the raw data\n\n"
        "Please use only the tools that are explicitly defined above."
    )

    messages = [{"role": "system", "content": system_message}]

    while True:
        try:
            try:
                user_input = input("You: ").strip()
            except EOFError:
                print()
                break
            if user_input.lower() in ["quit", "exit"]:
                break

            messages.append({"role": "user", "content": user_input})

            llm_response = get_llm_response(messages)
            logging.info("Assistant: %s", llm_response)
            messages.append({"role": "assistant", "content": llm_response})

            tool_result = await process_llm_response(llm_response, mcp_session)

            if tool_result is not None:
                messages.append({"role": "system", "content": tool_result})

                final_response = get_llm_response(messages)
                logging.info("Final response: %s", final_response)
                messages.append({"role": "assistant", "content": final_response})

        except KeyboardInterrupt:
            break


async def main() -> int | None:
    """Initialize and run the chat session."""
    from pathlib import Path

    if not LLM_API_KEY:
        logging.error("Environment variable LLM_API_KEY missing")
        logging.error(
            "Get API key at https://console.volcengine.com/ark/region:ark+cn-beijing/apiKey"
        )
        return 1

    aicc_config_path = str(Path(__file__).parent / "client_config.json")
    headers = {
        "aicc-config": aicc_config_path,
    }

    async with trusted_mcp_client(MCP_URL, headers=headers) as mcp_session:
        logging.info("Client initialized")

        await mcp_session.initialize()
        logging.info("MCP session initialized")

        await run_chatbot(mcp_session)
        logging.info("Exiting")


if __name__ == "__main__":
    import sys

    sys.exit(asyncio.run(main()))
