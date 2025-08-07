# BBOT Strikes Agent

The BBOT Agent integrates the [BBOT scanning framework](https://github.com/blacklanternsecurity/bbot) with Strikes to automate and scale reconnaissance. It builds a continuously updated graph of your target's attack surface in a Neo4j database, using agents to analyze the interconnected data, plan subsequent actions, and highlight high-value findings for human review.

## Quick Start

### 1. Install UV

`uv` is a fast Python package manager that handles project installation and execution.

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Windows
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### 2. Authenticate to the Dreadnode platform

If you haven't previously, login to a platform using `dreadnode login`:

```bash
dreadnode login --server https://self-hosted

# Validate your active profile
uv run dreadnode profile list

# Switch if neccesary
uv run dreadnode profile switch

# Or set your environment variables
export DREADNODE_API_KEY="your-api-token"
export DREADNODE_SERVER="http://self-hosted"
```

See more about configuration for the dreadnode sdk [in the docs](https://docs.dreadnode.io/strikes/usage/config)

### 3. Setup your inference model

This agent uses [Rigging](https://github.com/dreadnode/rigging) to interact with the LLMs, provide tools, and track inference data.

The first point of confusing is usually what to pass to the `--model` argument, which is treated as an [identifier](/open-source/rigging/topics/generators#identifiers) to Rigging. Usually, the model name works as expected, but sometimes you need to supply a prefix like `gemini/` or `ollama/`:

```
gpt-4.1
claude-4-sonnet-latest
ollama/llama3-70b
gemini/gemini-2.5-pro
```

You may also want to setup environment variables for provider authentication:

```bash
export OPENAI_API_KEY=...
export ANTHROPIC_API_KEY=...
export GEMINI_API_KEY=...
export GROQ_API_KEY=...
```

### 3. Run a Scan

All commands use `uv run`, which creates a self-contained virtual environment on the fly.

```bash
uv run bbot-agent --model gpt-4.1 --targets dreadnode.io dreadnode.io targets.txt
```

This command initiates an autonomous reconnaissance loop. The agent will start a managed Neo4j container, begin scanning the target, analyze results as they arrive, and decide on follow-up actions.

By default, it will save the run data under a `bbot-agent` project, and you can view it the platform:

- https://platform.dreadnode.io/strikes/projects/bbot-agent
- http://self-hosted/strikes/projects/bbot-agent

---

## Core Workflows

### Deployment Modes

The agent supports flexible deployment combinations of Neo4j and BBOT, allowing you to choose the approach that best fits your environment:

| Neo4j Mode | BBOT Mode | Use Case                                                |
| ---------- | --------- | ------------------------------------------------------- |
| Container  | Container | Full isolation, no dependencies needed                  |
| Container  | Local     | Fast BBOT execution with managed database (**default**) |
| External   | Container | Connect to existing Neo4j with isolated scans           |
| External   | Local     | Both services running natively                          |

**Mixed Mode - Local BBOT (default)**

```bash
# BBOT running locally, Neo4j in a container
uv run bbot-agent --model gpt-4.1 --targets dreadnode.io
```

**Mixed Mode - External Neo4j**

```bash
# BBOT running in a container, external Neo4j server
uv run bbot-agent --model gpt-4.1 --targets dreadnode.io \
  --with-container \
  --neo4j.uri "bolt://your-neo4j:7687" --neo4j.password "your-password"
```

**Full Container Mode**

```bash
# Neo4j + BBOT both in containers
uv run bbot-agent --model gpt-4.1 --targets dreadnode.io \
  --with-container
```

**Full Local Mode**

```bash
# BBOT running locally, external Neo4j server
uv run bbot-agent --model gpt-4.1 --targets dreadnode.io \
  --neo4j.uri "bolt://localhost:7687" --neo4j.password "your-password"
```

### Guided Reconnaissance

Use the `--task` flag to direct the agent's actions. It leverages the existing database as context for your instructions, allowing for complex, stateful operations. If not supplied, it is set to a sane default.

**Example: Multi-Stage Attack Plan**

```bash
# 1. Start with broad subdomain enumeration
uv run bbot-agent --model gpt-4.1 --targets targets.txt --task "Run a complete subdomain enumeration using the subdomain-enum preset."

# 2. Follow up with targeted web scans on the results
uv run bbot-agent --model gpt-4.1 --targets targets.txt --task "The database contains subdomain results. Now, run the 'web-basic' preset on all discovered web services that returned a 200 or 302 status code."

# 3. Deepen the analysis with vulnerability scanning
uv run bbot-agent --model gpt-4.1 --targets targets.txt --task "Web services and technologies have been identified. Run a targeted nuclei scan against all URLs associated with 'api' or 'dev' subdomains. Use templates with 'high' or 'critical' severity."
```

### Hybrid Workflow: Manual Scans, AI Analysis

This workflow provides maximum control by separating data collection from analysis. You run `bbot` scans using your own scripts and terminals, and then use the agent purely for analysis and next-step recommendations.

**Option 1: Neo4j Container + Manual BBOT**

Start a Neo4j container with a persistent volume to store all findings:

```bash
docker run --rm --name bbot-neo4j \
  -p 7474:7474 -p 7687:7687 \
  -v "$(pwd)/.neo4j:/data" \
  -e NEO4J_AUTH=neo4j/bbotislife \
  neo4j:latest
```

Then run BBOT locally or in a container:

```bash
# Local BBOT (requires BBOT installation)
bbot --yes --output-modules neo4j \
  --config modules.neo4j.uri=bolt://localhost:7687 \
  -t dreadnode.io -p web-screenshots

# Container BBOT (no dependencies)
docker run --rm -it \
  -v "$(pwd)/.bbot/config:/root/.config/bbot" \
  -v "$(pwd)/.bbot/scans:/root/.bbot/scans" \
  --add-host host.docker.internal:host-gateway
  blacklanternsecurity/bbot \
    --output-modules neo4j \
    --config modules.neo4j.uri=bolt://host.docker.internal:7687 \
    --yes -t dreadnode.io -p web-screenshots
```

_The `host.docker.internal` DNS name is a Docker feature that allows the BBOT container to connect to services running on your local machine (i.e., the Neo4j container). It's available by default on Docker Desktop, our can be enabled on other installations with the `--add-host` flag._

**Option 2: External Neo4j + Manual BBOT**

If you have an existing Neo4j instance, connect BBOT directly:

```bash
# Local BBOT to external Neo4j
bbot --yes --output-modules neo4j \
  --config modules.neo4j.uri=bolt://your-neo4j-server:7687 \
  modules.neo4j.username=neo4j modules.neo4j.password=your-password \
  -t dreadnode.io -p web-screenshots
```

**Analysis Phase**

Point the agent at your database for pure analysis (no scanning):

```bash
uv run bbot-agent \
  --model gpt-4.1 \
  --neo4j.uri "bolt://localhost:7687" \
  --task "Identify the top 10 new areas of interest to investigate"
```

### Dedicated Screenshot Analysis

Use a dedicated, multi-modal workflow to triage web screenshots and find high-value visual targets.

```bash
uv run bbot-agent screenshots --model gpt-4o --limit 50
```

This command queries the database for `WEBSCREENSHOT` nodes and uses the specified vision-capable model to evaluate each image. It identifies and prioritizes assets based on visual cues like login forms, admin dashboards, error messages, and outdated design, providing a summary and list of interesting elements for each.

---

## Running agent tools as an MCP server

Expose the entire `BbotTool` suite as a persistent server using the Model-Centric Protocol (MCP). This allows other applications, UIs, or agent systems to remotely call its functions (`run_scan`, `query`, etc.), turning the agent into a stateful reconnaissance backend.

This command starts all necessary services (including the Neo4j container) and listens for requests.

```bash
uv run bbot-agent mcp
# ...
# Started server process [94904]
# Waiting for application startup.
# Application startup complete.
# Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

The `mcp` command accepts all the same `--neo4j-*` and `--bbot-*` arguments for configuration.

### Add BBOT tools to Claude Code

```bash
$ claude mcp add bbot -t sse http://localhost:8000/sse
Added SSE MCP server bbot with URL: http://localhost:8000/sse to local config

$ claude
> /mcp

╭────────────────────────────────────────────────────────────────────────────────╮
| Manage MCP servers                                                             │
│                                                                                │
│ ❯ 1. bbot  ✔ connected · Enter to view details                                 │
|                                                                                │
╰────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────╮
│ Bbot MCP Server                                                                │
│                                                                                │
│ Status: ✔ connected                                                            │
│ URL: http://localhost:8000/sse                                                 │
│ Config location: /Users/user/.claude.json                                      │
│ Capabilities: tools                                                            │
│ Tools: 9 tools                                                                 │
│                                                                                │
│ ❯ 1. View tools                                                                │
╰────────────────────────────────────────────────────────────────────────────────╯

> Tell me about the most interesting subdomains
```

---

## Configuration & Technical Reference

### Command-Line Arguments

| Argument           | Purpose                               | Example                           |
| ------------------ | ------------------------------------- | --------------------------------- |
| `--model`          | **(Required)** LLM to use.            | `gpt-4o`, `ollama/llama3`         |
| `--task`           | Specific instruction for the agent.   | `"Find all API endpoints."`       |
| `--targets`        | Targets to scan; creates a whitelist. | `megacorp.com`, `10.0.0.0/24`     |
| `--presets`        | BBOT presets or local `.yml` files.   | `subdomain-enum`, `./presets.yml` |
| `--extra-args`     | Pass-through args for `bbot`.         | `'--proxy http://127.0.0.1'`      |
| `--with-container` | Run BBOT in container vs locally.     | `true` (default), `false`         |
| `--neo4j.uri`      | Connect to external Neo4j instance.   | `bolt://host:7687`                |
| `--neo4j.user`     | Neo4j username.                       | `neo4j` (default)                 |
| `--neo4j.password` | Neo4j password.                       | `bbotislife` (default)            |

### File-Based Configuration

The agent uses the local `.bbot/config` directory for BBOT configuration:

- **Global BBOT Config:** `.bbot/config/bbot.yml`
- **Secrets Management:** `.bbot/config/secrets.yml`. Keys must match BBOT module options.
  ```yaml
  # .bbot/config/secrets.yml
  modules:
    shodan:
      api_key: "sh_your_api_key"
  ```
- **Custom Presets:** Store `.yml` presets in `.bbot/presets/` and pass them via `--presets`.

**Configuration Behavior by Mode:**

- **Container Mode**: Mounts `.bbot/config` into the BBOT container at `/root/.config/bbot`
- **Local Mode**: BBOT reads from your system's config (typically `~/.config/bbot/bbot.yaml`). If this differs from `.bbot/config/bbot.yml`, the agent will warn you to keep them synchronized.

For example, here is how to setup a slack webhook module to execute for all the agent BBOT scans:

1. Place the following in `slack.yml`:

```yaml
config:
  modules:
    slack:
      webhook_url: https://hooks.slack.com/services/...

output_modules:
  - slack
```

2. Pass the presets when running the agent:

```bash
uv run bbot-agent ... --presets slack.yml
```

The preset file will automatically get mounted in the container and appended to all BBOT commands.

### Directory Structure

```
.
├── .bbot/
│   ├── config/         # Custom BBOT configs (bbot.yml, secrets.yml)
│   ├── presets/        # Your custom preset files
│   └── scans/          # Raw output and artifacts from every BBOT scan
└── .neo4j/             # The complete Neo4j graph database files
```

### Resetting Your Environment

To start completely fresh, remove the data directories.

```bash
# WARNING: This permanently deletes all saved scan data and graph history.
rm -rf .bbot/ .neo4j/
```
