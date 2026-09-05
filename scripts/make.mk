.DEFAULT_GOAL := help
COMPOSE := docker compose

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

up:        ## build (if needed) and start everything
	$(COMPOSE) up -d --build
	@echo "→ http://localhost:$${MF_PORT:-8000}"

down:      ## stop everything
	$(COMPOSE) down

restart:   ## restart the web app only (fast iteration)
	$(COMPOSE) restart web

rebuild:   ## rebuild all images from scratch
	$(COMPOSE) build --no-cache

logs:      ## tail all logs
	$(COMPOSE) logs -f --tail=120

logs-web:  ## tail the web app
	$(COMPOSE) logs -f --tail=200 web

logs-vol2: ## tail the Volatility 2 runner
	$(COMPOSE) logs -f --tail=200 vol2

logs-vol3: ## tail the Volatility 3 runner
	$(COMPOSE) logs -f --tail=200 vol3

ps:        ## container status
	$(COMPOSE) ps

health:    ## check both engines answer
	@curl -sS http://localhost:9003/health | head -c 400; echo
	@curl -sS http://localhost:9002/health | head -c 400; echo

shell-web:  ## shell inside the web container
	$(COMPOSE) exec web bash

shell-vol2: ## shell inside the Volatility 2 container
	$(COMPOSE) exec vol2 bash

shell-vol3: ## shell inside the Volatility 3 container
	$(COMPOSE) exec vol3 bash

reset-db:  ## DESTRUCTIVE: wipe the database, results and logs
	$(COMPOSE) down
	rm -rf data/volatilegui.sqlite3* data/results data/logs data/reports
	@echo "database wiped — 'make up' to start fresh"

.PHONY: help up down restart rebuild logs logs-web logs-vol2 logs-vol3 ps \
        health shell-web shell-vol2 shell-vol3 reset-db
