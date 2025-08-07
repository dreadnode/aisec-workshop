import ast
import sys
import typing as t
from dataclasses import dataclass
from pathlib import Path

import cyclopts
import dreadnode as dn
import litellm
import rigging as rg
from loguru import logger

from bbot_agent.prompts import analyze_screenshot, operator
from bbot_agent.tools import BbotTool, finish_task, highlight_for_review, update_todo

if t.TYPE_CHECKING:
    from loguru import Record as LogRecord

# Log formatting


def log_formatter(record: "LogRecord") -> str:
    return "".join(
        (
            "<green>{time:HH:mm:ss.SSS}</green> | ",
            "<dim>{extra[prefix]}</dim> " if record["extra"].get("prefix") else "",
            "<level>{message}</level>\n",
        )
    )


def setup_logging(log_level: str = "INFO") -> None:
    logger.remove()
    logger.add(sys.stderr, format=log_formatter, level=log_level)
    logger.enable("rigging")


setup_logging("INFO")

# CLI

app = cyclopts.App(help_on_error=True)


@cyclopts.Parameter(name="dn", group="Dreadnode")
@dataclass
class DreadnodeArgs:
    server: str | None = None
    """Dreadnode server URL"""
    token: str | None = None
    """Dreadnode API token"""
    project: str | None = "bbot-agent"
    """Dreadnode project name"""
    profile: str | None = None
    """Dreadnode profile name"""
    console: t.Annotated[bool, cyclopts.Parameter(negative=False)] = False
    """Show span information in the console"""
    log_level: str = "INFO"
    """Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"""

    def setup(self) -> None:
        setup_logging(self.log_level)
        dn.configure(
            server=self.server, token=self.token, project=self.project, console=self.console
        )


@cyclopts.Parameter(name="neo4j", group="Neo4j")
@dataclass
class Neo4jArgs:
    uri: str | None = None
    """Neo4j database URI (e.g., bolt://localhost:7687)"""
    user: str = "neo4j"
    """Neo4j database user"""
    password: str = "bbotislife"  # noqa: S105
    """Neo4j database password"""
    data_dir: Path | str = ".neo4j"
    """Directory to store Neo4j data when using a container"""


@cyclopts.Parameter(name="*", group="BBOT", negative=False)
@dataclass
class BbotArgs:
    extra_args: list[str] | None = None
    """Additional arguments to pass to BBOT commands"""
    whitelist: t.Annotated[
        list[str] | None, cyclopts.Parameter(negative=False, consume_multiple=True)
    ] = None
    """Whitelist parameters for BBOT commands (supports file paths)"""
    blacklist: t.Annotated[
        list[str] | None, cyclopts.Parameter(negative=False, consume_multiple=True)
    ] = None
    """Blacklist parameters for BBOT commands (supports file paths)"""
    presets: t.Annotated[
        list[str] | None, cyclopts.Parameter(negative=False, consume_multiple=True)
    ] = None
    """Presets to use for BBOT commands (supports file paths)"""
    data_dir: Path | str = ".bbot"
    """Directory to store BBOT data (default: .bbot)"""
    with_container: bool = False
    """Run BBOT inside an ephemeral container (avoids dependencies, but longer load times)"""


# Main agent

DEFAULT_TASK = "Perform the next best actionable recon for the provided targets and hightlight areas for review."


@app.default
async def agent(
    *,
    model: str,
    task: str = DEFAULT_TASK,
    targets: t.Annotated[
        list[str] | None, cyclopts.Parameter(negative=False, consume_multiple=True)
    ] = None,
    max_steps: int = 100,
    bbot_args: BbotArgs | None = None,
    neo4j_args: Neo4jArgs | None = None,
    dn_args: DreadnodeArgs | None = None,
) -> None:
    """
    Execute a BBOT agent task using the specified model and parameters.

    If `targets` is provided, it can be a list BBOT-compatible target strings, or file paths containing one target per line.

    One of `task` or `targets` must be provided.

    Args:
        model: The LLM model to use (e.g., "gpt-4.1", "ollama/llama-3.2")
            (see https://docs.dreadnode.io/open-source/rigging/topics/generators)
        task: The task to complete - otherwise a default task will be used
        targets: List of target hostnames or IPs to focus on
        max_steps: Maximum number of steps to allow
    """
    (dn_args or DreadnodeArgs()).setup()
    neo4j_args = neo4j_args or Neo4jArgs()
    bbot_args = bbot_args or BbotArgs()

    if not targets and not task:
        raise ValueError("Either 'task' or 'targets' must be provided")

    in_scope_targets: list[str] = []
    for target in targets or []:
        if (target_path := Path(target)).exists():
            with target_path.open("r") as f:  # noqa: ASYNC230
                in_scope_targets.extend(target.strip() for line in f if line.strip())
        else:
            in_scope_targets.append(target.strip())

    if in_scope_targets and not bbot_args.whitelist:
        logger.info("No whitelist provided, using the supplied targets")
        bbot_args.whitelist = in_scope_targets

    logger.info("Starting agent ...")
    logger.info(f" |- model:     {model}")
    logger.info(f" |- max_steps: {max_steps}")
    logger.info(f" |- task:      {task}")
    if in_scope_targets:
        logger.info(f" |- targets:   {len(in_scope_targets)}")

    bbot_tool = BbotTool(
        extra_args=bbot_args.extra_args,
        whitelist=bbot_args.whitelist,
        blacklist=bbot_args.blacklist,
        presets=bbot_args.presets,
        data_dir=bbot_args.data_dir,
        neo4j_uri=neo4j_args.uri,
        neo4j_user=neo4j_args.user,
        neo4j_password=neo4j_args.password,
        local=not bbot_args.with_container,
    )

    with dn.run(tags=["agent"]):
        dn.log_params(model=model, max_steps=max_steps)
        dn.log_inputs(
            task=task,
            targets=in_scope_targets,
            extra_args=bbot_args.extra_args,
            presets=bbot_args.presets,
        )

        async with bbot_tool as bbot:
            version = await bbot.get_bbot_version()
            logger.success(
                f"Using BBOT {version} ({'container' if bbot_args.with_container else 'local'})"
            )

            prompt = operator.render(task, targets=in_scope_targets or None)
            chat = (
                await rg.get_generator(model)
                .chat(prompt)
                .catch(*litellm.exceptions.LITELLM_EXCEPTION_TYPES, on_failed="include")
                .watch(rg.watchers.stream_to_logs)
                .using(finish_task, update_todo, highlight_for_review, bbot, max_depth=max_steps)  # type: ignore[arg-type]
                .name("BBOT Operator")
                .run()
            )

            if chat.failed and chat.error:
                if isinstance(chat.error, rg.error.MaxDepthError):
                    logger.warning(f"Max steps reached ({max_steps})")
                    dn.log_metric("max_steps_reached", 1)
                    dn.log_output("task_summary", f"Max steps ({max_steps}) reached", to="run")
                else:
                    logger.warning(f"Failed with {chat.error}")
                    dn.log_metric("inference_failed", 1)
                    dn.log_output("task_summary", f"Inference failed with {chat.error}", to="run")

            elif chat.last.role == "assistant":
                dn.log_output("last_message", dn.Markdown(chat.last.content), to="run")

    logger.info("Done.")


# Screenshot analysis


@app.command
async def screenshots(
    *,
    model: str,
    limit: int = 100,
    neo4j_args: Neo4jArgs | None = None,
    dn_args: DreadnodeArgs | None = None,
) -> None:
    """
    Analyze web screenshots individually using the specified model.

    Args:
        model: The LLM model to use - must support multi-modal inputs (e.g., "gpt-4o-mini")
            (see https://docs.dreadnode.io/open-source/rigging/topics/generators)
        limit: Maximum number of screenshots to analyze (default: 100)
    """
    if limit < 1:
        raise ValueError("Limit must be at least 1")

    (dn_args or DreadnodeArgs()).setup()
    neo4j_args = neo4j_args or Neo4jArgs()

    bbot_tool = BbotTool(
        neo4j_uri=neo4j_args.uri, neo4j_user=neo4j_args.user, neo4j_password=neo4j_args.password
    )

    with dn.run(tags=["screenshots"]):
        dn.log_params(model=model, limit=limit)

        async with bbot_tool as bbot:
            screenshots = await bbot.get_nodes("WEBSCREENSHOT")
            total_found = len(screenshots)

            if len(screenshots) == 0:
                logger.warning("No screenshots found")
                return

            if limit is not None and len(screenshots) > limit:
                screenshots = screenshots[:limit]
                logger.info(f"Found {total_found} screenshots, analyzing top {limit}")
            else:
                logger.info(f"Found {len(screenshots)} screenshots to analyze")

            pipeline = rg.get_generator(model).chat()

            for screenshot in screenshots:
                with dn.task_span("analyze_screenshot"):
                    data = screenshot.get("data", "{}")
                    data = ast.literal_eval(data)  # BBOT stores this weird
                    url = data.get("url", screenshot.get("uuid", "unknown"))

                    dn.log_input("url", url)

                    screenshot_content = await bbot.get_screenshot(uuid=screenshot["uuid"])
                    if not screenshot_content:
                        logger.warning("| - not found, skipping")
                        return

                    dn.log_input("screenshot", dn.Image(screenshot_content.to_bytes()))
                    dn.log_input("screenshot_metadata", screenshot)

                    analysis = await analyze_screenshot.bind(
                        pipeline.fork(rg.Message("user", [screenshot_content]))
                    )(screenshot)

                    priority = analysis.priority.lower()
                    priority_score = (
                        10
                        if priority == "critical"
                        else 7
                        if priority == "high"
                        else 3
                        if priority == "medium"
                        else 1
                    )
                    interesting_elements = analysis.elements.items

                    logger.success(f"|- {url}")
                    logger.info(f"   |- priority: {priority}")
                    logger.info(f"   |- elements: {','.join(interesting_elements)}")

                    dn.log_outputs(
                        priority=priority,
                        summary=dn.Markdown(analysis.summary),
                        elements=interesting_elements,
                    )

                    dn.tag(f"priority/{priority}")

                    dn.log_metric("priority", priority_score)
                    dn.log_metric("summary_lines", len(analysis.summary.splitlines()))
                    dn.log_metric("num_elements", len(interesting_elements), to="run")
                    dn.log_metric(f"{priority}_priority", 1, mode="count", to="run")

                dn.log_metric("screenshot_analyzed", 1, mode="count")


@app.command
async def mcp(
    *,
    transport: t.Literal["stdio", "sse", "streamable-http"] = "sse",
    bbot_args: BbotArgs | None = None,
    neo4j_args: Neo4jArgs | None = None,
) -> None:
    """
    Load the agent BBOT toolset and expose it as an MCP server.

    Args:
        transport: The transport to use for the MCP server (stdio, sse, streamable-http)
    """
    setup_logging("INFO")

    bbot_args = bbot_args or BbotArgs()
    neo4j_args = neo4j_args or Neo4jArgs()

    bbot_tool = BbotTool(
        extra_args=bbot_args.extra_args,
        whitelist=bbot_args.whitelist,
        blacklist=bbot_args.blacklist,
        presets=bbot_args.presets,
        data_dir=bbot_args.data_dir,
        neo4j_uri=neo4j_args.uri,
        neo4j_user=neo4j_args.user,
        neo4j_password=neo4j_args.password,
    )

    async with bbot_tool as bbot:
        mcp_server = rg.as_mcp(bbot)

        match transport:
            case "stdio":
                await mcp_server.run_stdio_async()
            case "sse":
                await mcp_server.run_sse_async("/")
            case "streamable-http":
                await mcp_server.run_streamable_http_async()


if __name__ == "__main__":
    app()
