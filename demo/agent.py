# -*- coding: utf-8 -*-
# Copyright (c) 2025 Beijing Volcano Engine Technology Co., Ltd. and/or its affiliates
# SPDX-License-Identifier: MIT

import json
import logging
import os
import threading
import time
import httpx
import mcp
# from datetime import datetime, timezone
import uuid
import queue
import asyncio

from volcenginesdkarkruntime._utils import deepcopy_minimal
from response_util import ResponseUtil
from flask import Flask, request, jsonify
from bytedance.jeddak_trusted_mcp import trusted_mcp_client
from volcenginesdkarkruntime import Ark
import bytedance.jeddak_secure_channel as jsc


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


class McpAgent:
    def __init__(self):
        self.MCP_URL = os.environ.get("MCP_URL")
        self.LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "**")
        self.LLM_API_KEY = os.environ.get("LLM_API_KEY", "**")
        self.LLM_MODEL_NAME = os.environ.get("LLM_MODEL_NAME", "**")
        self.TRUSTED_API_KEY = os.environ.get("TRUSTED_API_KEY", "**")
        self.TRUSTED_EP = os.environ.get("TRUSTED_EP", "**")

        self.task_queue = queue.Queue()
        self.task_info = dict()
        self.stop_service = False

        task_thread = threading.Thread(target=self.task_proc, args=())
        task_thread.start()

    def get_llm_response(self, messages: list[dict[str, str]]) -> str:
        """
        Get a response from the LLM
        :param messages:
        :return:
        """
        url = self.LLM_BASE_URL + "/chat/completions"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.LLM_API_KEY}",
        }

        payload = {
            "messages": messages,
            "model": self.LLM_MODEL_NAME,
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

    def get_trust_llm_response(self, messages: list[dict[str, str]]) -> str:
        """
        Get a response from the trusted LLM
        :param messages:
        :return:
        """
        client = Ark(api_key=self.TRUSTED_API_KEY)
        thinking = {
            "type": "disabled"  # 关闭思考模式
        }
        resp = client.chat.completions.create(
            model=self.TRUSTED_EP,
            messages=messages,
            thinking=thinking,
            stream=False,
            extra_headers={"x-is-encrypted": "true", "x-ark-moderation-scene": "skip-ark-moderation"}
            # x-ark-moderation-scene=skip-ark-moderation 表示跳过内容审核
        )
        return resp.choices[0].message.content

    async def process_llm_response(self, llm_response: str, mcp_session: mcp.ClientSession,
                                   task_id: str, open_trust: int) -> str | None:
        """
        Process the LLM response and execute tools if needed
        :param llm_response:
        :param mcp_session:
        :param task_id:
        :param open_trust:
        :return:
        """
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
            self.update_task_info(task_id, 3, json.dumps(tool_call["arguments"]), open_trust)
            result = await mcp_session.call_tool(tool_call["tool"], tool_call["arguments"])
            self.update_task_info(task_id, 4, f"{result}", open_trust)

            return f"Tool execution result: {result}"
        except Exception as e:
            error_msg = f"Error executing tool: {str(e)}"
            logging.error(error_msg)
            return error_msg

    def format_tool_for_llm(self, tool: mcp.Tool) -> str:
        """
        Format tool information for LLM.
        Returns:
            A formatted string describing the tool.
        :param tool:
        :return:
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

    def random_str(self, count=6, pre=None):
        tmp = str(uuid.uuid4())
        ret = ''.join(tmp.split('-'))[-count:]
        if pre:
            return pre + ret
        else:
            return ret

    def query_weather(self, task_id: str, query: str, open_trust: int):
        """
        query_weather
        :param task_id:
        :param query:
        :param open_trust:
        :return:
        """
        self.task_queue.put((task_id, query, open_trust))

        res = {
            "TrustedInfo": {
                "Agent": open_trust,
                "LLM": open_trust,
                "Client": open_trust,
                "Server": open_trust
            },
            "MsgInfo": {
                "CuPhase": 0,
                "IsFinished": False,
                "Infos": [
                ]
            },
            "Weather": ""
        }
        self.task_info[task_id] = res

    def get_task_info(self, task_id: str) -> dict:
        """
        :param task_id:
        :return:
        """
        return self.task_info.get(task_id)

    def do_weather_debug(self, task_id, query, open_trust):
        res = {
            "TrustedInfo": {
                "Agent": open_trust,
                "LLM": open_trust,
                "Client": open_trust,
                "Server": open_trust
            },
            "MsgInfo": {
                "CuPhase": 4,
                "IsFinished": True,
                "Infos": [
                    {
                        "Phase": 1,
                        "Name": "agent->llm",
                        "info": "Choose the appropriate tool based on the user's question. If no tool is needed"
                    },
                    {
                        "Phase": 2,
                        "Name": "llm->agent",
                        "info": "{\"tool\": \"get_weather\",     \"arguments\": {         \"city\": \"北京\"     }"
                    },
                    {
                        "Phase": 3,
                        "Name": "client->server",
                        "info": "{hoose the appropriate tool based on the user's question. If no tool is needed}"
                    },
                    {
                        "Phase": 4,
                        "Name": "server->client",
                        "info": "{hoose the appropriate tool based on the user's question. If no tool is needed}"
                    }
                ]
            },
            "Weather": "spDsJ3y2IG"
        }
        self.task_info[task_id] = res

    def update_task_info(self, task_id: str, phase: int, info: str, open_trust: int):
        """
        :param task_id:
        :param phase:
        :param info:
        :param open_trust:
        :return:
        """
        if task_id in self.task_info:
            task_info = self.task_info.get(task_id)
        else:
            task_info = dict()

        task_info["TrustedInfo"] = {
            "Agent": open_trust,
            "LLM": open_trust,
            "Client": open_trust,
            "Server": open_trust
        }

        if "MsgInfo" not in task_info:
            task_info["MsgInfo"] = dict()

        if phase < 5:
            task_info["MsgInfo"]["CuPhase"] = phase
            task_info["MsgInfo"]["IsFinished"] = False

            if "Infos" not in task_info["MsgInfo"]:
                task_info["MsgInfo"]["Infos"] = list()

            if open_trust == 1 and (phase == 3 or phase == 4):
                jsc_config = jsc.ClientConfig.from_dict({"pub_key_path": "./myPublicKey.pem"})
                jsc_client = jsc.Client(jsc_config)
                encrypted, _ = jsc_client.encrypt_with_response(info)
                cur_info = {"Phase": phase, "info": encrypted}
            else:
                cur_info = {"Phase": phase, "info": info}

            if phase == 1:
                cur_info["Name"] = "Agent - 可信豆包"
            elif phase == 2:
                cur_info["Name"] = "可信豆包 - Agent"
            elif phase == 3:
                cur_info["Name"] = "MCP Client - MCP Server"
            elif phase == 4:
                cur_info["Name"] = "MCP Server - MCP Client"

            task_info["MsgInfo"]["Infos"].append(cur_info)
        elif phase == 5:
            task_info["MsgInfo"]["IsFinished"] = True
            task_info["Weather"] = info

        self.task_info[task_id] = task_info

    async def do_weather(self, task_id, query, open_trust):
        try:
            async with trusted_mcp_client(self.MCP_URL) as mcp_session:
                await mcp_session.initialize()

                tools = (await mcp_session.list_tools()).tools
                tools_description = "\n".join(self.format_tool_for_llm(tool) for tool in tools)

                system_message = (
                    "You are a helpful assistant with access to these tools:\n\n"
                    f"{tools_description}\n"
                    "Choose the appropriate tool based on the user's question. "
                    "If no tool is needed, reply directly.\\n\\n"
                    "IMPORTANT: When you need to use a tool, you must ONLY respond with "
                    "the exact JSON object format below, nothing else:\\n"
                    "{\\n"
                    '    \"tool\": \"tool-name\",\\n'
                    '    \"arguments\": {\\n'
                    '        \"argument-name\": \"value\"\\n'
                    "    }\\n"
                    "}\\n\\n"
                    "After receiving a tool\'s result:\\n"
                    "1. Transform the raw data into a natural, conversational response\\n"
                    "2. Keep responses concise but informative\\n"
                    "3. Focus on the most relevant information\\n"
                    "4. Use appropriate context from the user\'s question\\n"
                    "5. Avoid simply repeating the raw data\\n\\n"
                    "Please use only the tools that are explicitly defined above."
                )

                messages = [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": query}
                ]

                trust_messages = deepcopy_minimal(messages)

                llm_response = self.get_trust_llm_response(trust_messages)
                # logging.info(f"messages: {messages}")
                self.update_task_info(task_id, 1, json.dumps(trust_messages), open_trust)

                logging.info("Assistant: %s", llm_response)
                self.update_task_info(task_id, 2, json.dumps(llm_response), open_trust)

                messages.append({"role": "assistant", "content": llm_response})

                tool_result = await self.process_llm_response(llm_response, mcp_session, task_id, open_trust)
                logging.info(f"tool_result: {tool_result}")
                if tool_result is not None:
                    messages.append({"role": "system", "content": tool_result})
                    final_response = self.get_llm_response(messages)
                    logging.info("Final response: %s", final_response)
                    self.update_task_info(task_id, 5, final_response, open_trust)
                else:
                    self.update_task_info(task_id, 5, json.dumps(llm_response), open_trust)

                messages.append({"role": "assistant", "content": final_response})

        except Exception as e:
            logging.error(f"An error occurred in chat API: {e}")
            return ResponseUtil.fail(str(e), "POST"), 400

    def task_proc(self):
        while not self.stop_service:
            try:
                task = self.task_queue.get()
                task_id = task[0]
                query = task[1]
                open_trust = task[2]
                print(f'task manager: start proc {task_id} ...')
                asyncio.run(self.do_weather(task_id, query, open_trust))
                print(f'task manager: end proc {task_id} ...')

            except Exception as e:
                print(f"task manager: get task from queue error, msg={e}")
            finally:
                # time.sleep(5)
                continue


mcp_agent = McpAgent()

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False


@app.before_request
def before_request():
    # uid = request.headers.get("uid", "1")
    token = request.headers.get("token")
    # timestamp = request.headers.get("timestamp", "")

    if not token.startswith("jeddak.trusted.mcp"):
        return jsonify({"error": "'token' error"}), 400

    return None


@app.route('/ping')
def ping():
    return "Hello Trusted MCP"


@app.route("/api/mcp/demo/query_weather", methods=["POST"])
def query_weather():
    body = request.get_json()
    user_input = body.get("query")
    open_trust = int(body.get("OpenTrust", "1"))

    if not user_input:
        return ResponseUtil.fail("Missing 'query' in request", "POST"), 400

    task_id = mcp_agent.random_str(pre="mcp_")

    mcp_agent.query_weather(task_id, user_input, open_trust)

    res = {"TaskId": task_id}
    return ResponseUtil.success(res, "POST"), 200


@app.route("/api/mcp/demo/get_weather_info", methods=["GET"])
def get_weather_info():
    body = request.args
    task_id = body.get("TaskId")

    if not task_id:
        return ResponseUtil.fail("Missing 'task_id' in request", "GET"), 400

    res = mcp_agent.get_task_info(task_id)
    if res:
        return ResponseUtil.success(res, "GET"), 200
    else:
        return ResponseUtil.fail("no this task", "GET"), 400


if __name__ == "__main__":
    # run flask server
    app.run(host="0.0.0.0", port=5000)
