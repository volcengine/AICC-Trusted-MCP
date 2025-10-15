# AICC-Trusted MCP介绍
Trusted MCP是在Jeddak AICC的基础上实现的可信MCP解决方案，Trusted MCP充分利用Jeddak AICC端云互信等能力，为MCP的核心组件提供身份证明和证明验证能力，并在此基础上提供了全流程的通信加密方案，确保MCP核心组件及组件间通信数据的安全，解决MCP应用中服务身份不可信、数据被篡改、流量劫持、数据隐私泄露等安全威胁。
# 主要模块
AICC-Trusted MCP 分为四个模块，即 AI Agent、机密豆包、MCP Client 和 MCP Server。在用户 query 的 pipeline 里，用户首先向 AI agent 提出 query。AI agent 收到 query 后，会请求机密豆包解析用户 query 中的具体任务请求，并将其转化为结构化的工具调用输入，然后传输给 MCP Client。接下来，MCP Client 依据 Trusted MCP 协议，将密文 arguments 传输给 MCP server，得到对应的密文 results。随后，MCP Client 会解密，并把明文 results 返回给用户。
# 使用说明：
##SDK编译
进入AICC 端云互信开源代码，执行编译脚本：
`sh  build.sh`
编译产物在dist目录中。

##SDK安装（依赖 Python >= 3.10）。
进入dist目录执行pip命令安装SDK
```
version=0.0.1
pip install bytedance_jeddak_trusted_mcp-${version}-py3-none-any.whl
```

##设置运行时配置
1. 【可选】生成加解密需要的默认公钥和私钥（非AICC部署模式）
   执行如下命令生成 myPrivateKey.pem和myPublicKey.pem
   ```
   openssl genrsa -out ./myPrivateKey.pem 4096
   openssl rsa -pubout -in ./myPrivateKey.pem -out ./myPublicKey.pem
   ```
2. 【可选】准备AICC配置文件
   MCP Server运行配置
   ```
   {
   "tks_url": "pcc.volcengineapi.com", //固定不需要修改
   "tks_app_id": "2100xxxxxx",//火山引擎账号ID
   "bytedance_top_info": "{\"ak\": \"***\", \"sk\": \"***\", \"service\": \"pcc\"}",
   "refresh_interval": 3600
   }
   ```
   MCP Client运行配置
   ```
   {
   "ra_url": "pcc.volcengineapi.com",// 固定不变
   "ra_service_name": "rag_client_test", //接收端服务在Jeddak AICC上部署时的服务名称
   "ra_policy_id": "16a371d7-130b-xxxxxxxxx-b5xxxxxxxxad8",//做远程证明时的策略ID
   "ra_uid": "2100xxxxxx",
   "bytedance_top_info": "{\"ak\": \"***\", \"sk\": \"**\", \"service\": \"pcc\"}",
   "attest_interval": 600
   }
   ```
##运行demo
###本地方式运行
   启动MCP server
```
   python server.py
```
   启动MCP client
   注意，启动demo MCP client需要先申请火山方舟的API Key，如果没有可以联系火山获取一个临时key
   设置LLM_API_KEY环境变量
```
   export LLM_API_KEY=*****
   python client.py
 ```
###本地运行并显示MCP协议交互内容
   为了更直观地观察Trusted MCP Client和Server之间的协议交互的内容，例如MCP能力协商阶段交互协议内容以及确认Client和Server之间的通信过程是否加密，可借助socat工具来进行观察，使用步骤如下：
####socat工具安装
以Mac为例
```
brew install socat
```
- 启动socat，并建立8000到8001端口的转发
  ```
  socat -v TCP-LISTEN:8000,bind=127.0.0.1,fork TCP:127.0.0.1:8001
  ```
- 启动MCP server并监听8001端口
  ```
  python server.py --port 8001
  ```
- 启动MCP client（默认会访问8000端口）
  ```
  python client.py
  ```
  在Client和Server之间进行交互过程中，用户可通过观察 socat 窗口，获取 initialize 阶段 JSON-RPC 的具体内容，同时也可以确认在后续的Client和Server通信时启用了加密功能（补充说明Trusted MCP采用的是Jeddak AICC端云互信的加密能力对通信内容进行加密，每次加密的密钥都是随机的，也即相同的query，两次加密的密文并不会相同）。
####AICC方式运行
   我们将server.py也在AICC的环境中进行了部署（服务地址：http://180.184.47.108:8000/mcp），如果发现服务连接不上，请及时联系火山AICC团队排查服务状态。
1. 准备AICC配置
   火山AK、SK请联系火山AICC团队获取
   将AK、SK填到client_config.json文件中
   ```
   {
   "ra_service_name": "mcp_server_demo",
   "ra_policy_id": "4d2229dd-cee6-5a02-b3e7-847ea2bfcbdb",
   "ra_uid": "2102299836",
   "bytedance_top_info": "{\"url\": \"open.volcengineapi.com\", \"ak\": \"***\", \"sk\": \"****\", \"service\": \"pcc_test\"}"
   }
   ```
2. 启动client
   ```
   python aicc_client.py
   ```
#致谢
   感谢本项目成员，没有大家的共同努力，不会有这个项目的开源发布。希望本项目能对AI应用的隐私保护，特别是在涉及端云协作的场景下，迈出探索性的一步。
#license
   MIT。
