.PHONY: up compose

AGENT_VERSION = v1.0_250905_1
CLIENT_VERSION = v1.0_250905_1
SERVER_VERSION = v1.0_250905_1

# Build Docker Image
agent:
	echo 'docker build -t mcp_agent:$(AGENT_VERSION) -f ./agent.dockerfile . | tail -n 1 | cut -d' ' -f3 | xargs -t -I{} docker tag {} jeddak-cc-infra-cn-beijing.cr.volces.com/trusted_mcp_example/mcp_agent:$(AGENT_VERSION)'
	docker buildx build --platform linux/arm64 --no-cache -t mcp_agent:$(AGENT_VERSION) -f ./agent.dockerfile .
	echo 'mcp_agent:$(AGENT_VERSION)' | tail -n 1 | cut -d' ' -f3 | xargs -t -I{} docker tag {} jeddak-cc-infra-cn-beijing.cr.volces.com/trusted_mcp_example/mcp_agent:$(AGENT_VERSION)
	@echo "build mcp_agent docker image ok"

client:
	echo 'docker build -t mcp_client_example:$(CLIENT_VERSION) -f ./client.dockerfile . | tail -n 1 | cut -d' ' -f3 | xargs -t -I{} docker tag {} jeddak-cc-infra-cn-beijing.cr.volces.com/trusted_mcp_example/mcp_client:$(CLIENT_VERSION)'
	docker build -t mcp_client_example:$(CLIENT_VERSION) -f ./client.dockerfile .
	echo 'mcp_client_example:$(CLIENT_VERSION)' | tail -n 1 | cut -d' ' -f3 | xargs -t -I{} docker tag {} jeddak-cc-infra-cn-beijing.cr.volces.com/trusted_mcp_example/mcp_client:$(CLIENT_VERSION)
	@echo "build mcp_client_example docker image ok"

server:
	echo 'docker build -t mcp_server_example:$(SERVER_VERSION) -f ./server.dockerfile . | tail -n 1 | cut -d' ' -f3 | xargs -t -I{} docker tag {} jeddak-cc-infra-cn-beijing.cr.volces.com/trusted_mcp_example/mcp_server:$(SERVER_VERSION)'
	docker build -t mcp_server_example:$(SERVER_VERSION) -f ./server.dockerfile .
	echo 'mcp_server_example:$(SERVER_VERSION)' | tail -n 1 | cut -d' ' -f3 | xargs -t -I{} docker tag {} jeddak-cc-infra-cn-beijing.cr.volces.com/trusted_mcp_example/mcp_server:$(SERVER_VERSION)
	@echo "build mcp_server_example docker image ok"

# Push docker images
push_agent:
	docker push jeddak-cc-infra-cn-beijing.cr.volces.com/trusted_mcp_example/mcp_agent:$(AGENT_VERSION)

push_client:
	docker push jeddak-cc-infra-cn-beijing.cr.volces.com/trusted_mcp_example/mcp_client:$(CLIENT_VERSION)

push_server:
	docker push jeddak-cc-infra-cn-beijing.cr.volces.com/trusted_mcp_example/mcp_server:$(SERVER_VERSION)
