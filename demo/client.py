# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

import asyncio
import json
import logging
import os
import httpx
import mcp

from flask import Flask, request, jsonify
from bytedance.jeddak_trusted_mcp import trusted_mcp_client

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

MCP_URL = os.environ.get("MCP_URL", "**")

LLM_BASE_URL = os.environ.get(
    "LLM_BASE_URL", "**"
)
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
LLM_MODEL_NAME = os.environ.get("LLM_MODEL_NAME", "**")

app = Flask(__name__)


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


@app.route("/toolcall", methods=["POST"])
async def toolcall():
    """
    API request, receiving JSON format request body, return with LLM's response.
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    llm_response = request.json.get("response")
    if not llm_response:
        return jsonify({"error": "Missing 'response' in request"}), 400

    try:
        async with trusted_mcp_client(MCP_URL) as mcp_session:
            await mcp_session.initialize()

            # Process the initial LLM response to execute a tool, if any
            tool_result = await process_llm_response(llm_response, mcp_session)
            return jsonify({"tool_requrest": llm_response,"tool_response": tool_result})

    except Exception as e:
        import traceback
        logging.error(f"An error occurred in chat API: {e}")
        logging.error(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    # run flask server
    app.run(host="0.0.0.0", port=5001)
