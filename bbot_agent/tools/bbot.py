import ast
import asyncio
import contextlib
import json
import re
import shlex
import textwrap
import typing as t
from pathlib import Path

import dreadnode as dn
import rich
import rigging as rg
from loguru import logger
from rich.prompt import Prompt

from bbot_agent.tools.docker import ContainerConfig, container
from bbot_agent.tools.neo4j import Neo4jTool


def _parse_serialized_dict(data: str) -> t.Any:
    """
    Attempt to parse and decode string representations
    of JSON or Python literals into dictionaries.
    """
    if not isinstance(data, str):
        return data

    with contextlib.suppress(Exception):
        result = json.loads(data)
        return result if isinstance(result, dict) else {}

    with contextlib.suppress(Exception):
        result = ast.literal_eval(data)
        return result if isinstance(result, dict) else {}

    return data


def _summarize(data: dict[str, t.Any]) -> dict[str, t.Any]:
    summary: dict[str, t.Any] = {}

    # Always include these fields if they exist
    essential_fields = [
        "id",
        "type",
        "data",
        "host",
        "netloc",
        "port",
        "tags",
        "scope_description",
        "scope_distance",
    ]

    for field in essential_fields:
        if field in data and data[field] is not None:
            value = data[field]

            # Truncate long lists
            if isinstance(value, list):
                if len(value) > 5:  # noqa: PLR2004
                    summary[field] = value[:5]
                    summary[f"{field}_truncated"] = True
                else:
                    summary[field] = value

            # Truncate long strings
            elif isinstance(value, str) and len(value) > 200:  # noqa: PLR2004
                summary[field] = value[:200] + "..."
            else:
                summary[field] = value

    # Shorten ID if it's too long
    if "id" in summary and isinstance(summary["id"], str) and len(summary["id"]) > 40:  # noqa: PLR2004
        summary["id"] = summary["id"][:40] + "..."

    return summary


class BbotTool(Neo4jTool):
    """
    A unified tool for running BBOT scans and querying the results.
    """

    def __init__(
        self,
        image: str = "blacklanternsecurity/bbot:latest",
        data_dir: Path | str = ".bbot",
        *,
        extra_args: list[str] | None = None,
        whitelist: list[str] | None = None,
        blacklist: list[str] | None = None,
        presets: list[str] | None = None,
        scan_timeout: int = 3600,
        neo4j_uri: str | None = None,
        neo4j_user: str = "neo4j",
        neo4j_password: str = "bbotislife",  # noqa: S107
        neo4j_image: str = "neo4j:latest",
        neo4j_data_dir: Path | str = ".neo4j",
        neo4j_container_config: ContainerConfig | None = None,
        local: bool = True,
    ):
        """
        Initializes the BbotTool, which includes a Neo4j instance.

        Args:
            image: The Docker image to use for BBOT.
            data_dir: Directory to store BBOT data (default: ".bbot").
            extra_args: Additional command-line arguments for BBOT.
            whitelist: List of files or directories to whitelist for BBOT scans.
            blacklist: List of files or directories to blacklist for BBOT scans.
            presets: List of preset configurations to use for BBOT scans.
            scan_timeout: Timeout for BBOT scans in seconds (default: 3600).
            neo4j_uri: The URI for the Neo4j database.
            neo4j_user: Username for the Neo4j database (default: "neo4j").
            neo4j_password: Password for the Neo4j database (default: "bbotislife").
            neo4j_image: Docker image for the Neo4j database (default: "neo4j:latest").
            neo4j_data_dir: Directory to store Neo4j data (default: ".neo4j").
            neo4j_container_config: Optional configuration for the Neo4j container.
            local: If True, run BBOT scans locally instead of in a container.
        """
        super().__init__(
            username=neo4j_user,
            uri=neo4j_uri,
            password=neo4j_password,
            image=neo4j_image,
            data_dir=neo4j_data_dir,
            container_config=neo4j_container_config,
        )

        self.local = local
        self.bbot_image = image
        self.bbot_home = Path(data_dir).expanduser().resolve()

        self.extra_args = extra_args or []
        self.whitelist = whitelist or []
        self.blacklist = blacklist or []
        self.presets = presets or []
        self.scan_timeout = scan_timeout

        self._config_dir = self.bbot_home / "config"
        self._scan_dir = self.bbot_home / "scans"
        self._config_dir.mkdir(parents=True, exist_ok=True)
        self._scan_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"BBOT working out of {self.bbot_home}")

    async def get_bbot_version(self) -> str:
        """
        Retrieves the BBOT version by running 'bbot --version' in the container.
        """
        if not self.local:
            return self.image

        command = "bbot --version"
        exit_code, output = await self._run_locally(command, stream_output=False)
        if exit_code != 0:
            raise RuntimeError(
                f"Failed to get BBOT version - is `bbot` installed? ({exit_code}): {output.strip()}"
            )
        return next(iter(re.findall(r"^v[\d\.\w\-\+]+$", output, re.MULTILINE)), "unknown")

    async def _run_locally(
        self, command_str: str, *, stream_output: bool = True
    ) -> tuple[int, str]:
        args = shlex.split(command_str)
        process: asyncio.subprocess.Process | None = None
        returncode: int | None = None

        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,  # Redirect stderr to stdout
            )

            output_chunks = []

            async def stream() -> None:
                with logger.contextualize(prefix="bbot"):
                    if not process or not process.stdout:
                        return
                    while True:
                        line = await process.stdout.readline()
                        if not line:
                            break
                        decoded_line = line.decode(errors="replace").strip()
                        output_chunks.append(decoded_line)
                        if stream_output:
                            logger.info(decoded_line)

            await asyncio.wait_for(stream(), timeout=self.scan_timeout)
            await process.wait()

            returncode = process.returncode if process else 1
        except asyncio.TimeoutError:
            logger.warning(f"Local command timed out after {self.scan_timeout}s")
            if process:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
            return 124, "\n".join(output_chunks)
        except FileNotFoundError:
            logger.error(
                f"The command '{args[0]}' was not found. Is BBOT installed and in your PATH?"
            )
            return 1, f"Command not found: {args[0]}"
        except OSError as e:
            logger.error(f"Error running local command: {e}")
            return 1, str(e)

        return 1 if returncode is None else returncode, "\n".join(output_chunks)

    async def _run_in_container(
        self, command_str: str, container_volumes: dict[str | Path, str]
    ) -> tuple[int, str]:
        async with container(
            self.bbot_image,
            ContainerConfig(command=["sleep", "infinity"], volumes=container_volumes),
        ) as ctx:
            return await ctx.run(command_str, timeout=self.scan_timeout, stream_output=True)

    @rg.tool_method(catch=True, truncate=5_000)
    async def run_scan(  # noqa: PLR0912, PLR0915
        self,
        targets: list[str],
        modules: list[str] | None = None,
        presets: list[str] | None = None,
        flags: list[str] | None = None,
        config: list[str] | None = None,
        extra_args: list[str] | None = None,
    ) -> str:
        r"""
        Executes a BBOT scan against the specified targets.

        This is the primary action tool. It assembles and runs a `bbot` command
        in an ephemeral container, automatically configuring it to report findings
        to the currently active Neo4j database.

        Args:
            targets: REQUIRED. Targets to scan (e.g., ['example.com']).
            modules: Modules to run (e.g., ['httpx', 'nuclei']).
            presets: Presets to use (e.g., ['subdomain-enum', 'web-basic']).
            flags: Flags to enable module groups (e.g., ['passive', 'safe']).
            config: Custom config options in key=value format (e.g., ['modules.httpx.timeout=5']).
            extra_args: An array of strings for any other `bbot` CLI flags. This is the escape hatch
                        for advanced usage. For example:
                        ['--strict-scope']
                        ['-ef aggressive --allow-deadly']
                        ['--proxy http://127.0.0.1:8080']

        Returns:
            The standard output from the bbot command, summarizing the scan.
        """
        if not targets:
            raise ValueError("At least one target is required to run a scan.")

        # Resolve the neo4j uri

        if not self.uri or not self.auth:
            raise ValueError("Neo4j must be configured to run a scan.")

        neo4j_user, neo4j_password = self.auth
        neo4j_uri = self.uri

        if not self.local:
            neo4j_uri = neo4j_uri.replace("localhost", "host.docker.internal").replace(
                "127.0.0.1", "host.docker.internal"
            )
            logger.info(f"Using Neo4j URI: {neo4j_uri} (in container mode)")

        config = config or []
        config.extend(
            [
                f"modules.neo4j.uri={neo4j_uri}",
                f"modules.neo4j.username={neo4j_user}",
                f"modules.neo4j.password={neo4j_password}",
            ]
        )

        # Print a warning if the configs don't match
        if self.local:
            user_config_path = Path("~/.config/bbot/bbot.yaml").expanduser().resolve()
            repo_config_path = self._config_dir / "bbot.yaml"
            if (
                user_config_path.exists()
                and repo_config_path.exists()
                and user_config_path.read_text() != repo_config_path.read_text()
            ):
                logger.warning(
                    f"User and repo `bbot.yml` config files differ. When running BBOT locally, "
                    f"BBOT always reads from {user_config_path} - update settings there as needed."
                )

        # Assemble the BBOT command

        command_parts = ["bbot", "--yes", "--output-modules neo4j", "--brief"]

        if targets:
            command_parts.extend(["--targets", *targets])
        if modules:
            command_parts.extend(["--modules", *modules])
        if flags:
            command_parts.extend(["--flags", *flags])

        # Apply whitelist, blacklist, and presets - resolving file mounts if necessary

        whitelist = list(self.whitelist)
        blacklist = list(self.blacklist)
        presets = [*(presets or []), *self.presets]

        container_volumes: dict[str | Path, str] = {
            self._config_dir: "/root/.config/bbot",
            self._scan_dir: "/root/.bbot/scans",
        }

        if not self.local:
            for i, entry in enumerate(whitelist):
                if (entry_path := Path(entry)).exists():
                    container_path = f"/root/.bbot/whitelist/{entry_path.name}"
                    container_volumes[entry] = whitelist[i] = container_path

            for i, entry in enumerate(blacklist):
                if (entry_path := Path(entry)).exists():
                    container_path = f"/root/.bbot/blacklist/{entry_path.name}"
                    container_volumes[entry] = blacklist[i] = container_path

            for i, preset in enumerate(presets):
                if (preset_path := Path(preset)).exists():
                    container_path = f"/root/.bbot/presets/{preset_path.name}"
                    container_volumes[preset] = presets[i] = container_path

        if whitelist:
            command_parts.extend(["--whitelist", *whitelist])
        if blacklist:
            command_parts.extend(["--blacklist", *blacklist])
        if presets:
            command_parts.extend(["--preset", *presets])

        if config:
            command_parts.extend(["--config", *config])
        if extra_args := [*(extra_args or []), *self.extra_args]:
            command_parts.extend(extra_args)

        command_str = " ".join(command_parts)
        dn.log_input("scan_command", command_str)

        # Let the user approve the command

        if "--allow-deadly" in command_str:
            logger.error("Requested scan includes --allow-deadly.")

        wrapped_command = textwrap.fill(
            command_str, break_long_words=False, subsequent_indent=" " * 5
        )
        logger.info(f"Agent wants to run:\n{wrapped_command}")
        rich.print()
        if Prompt.ask("Run this scan?", choices=["y", "n"], default="y") == "n":
            return "Scan cancelled by user."

        # Execute in the container or locally
        exit_code, output = await (
            self._run_locally(command_str)
            if self.local
            else self._run_in_container(command_str, container_volumes)
        )

        if exit_code != 0:
            logger.error(f"BBOT scan exited with code {exit_code}:\n{output}")
            raise RuntimeError(f"BBOT scan failed:\n{output}")

        # Find the scan id and log the folder as an artifact
        if latest_scan_id := re.search(r"Starting scan (\w+)", output):
            scan_folder = self._scan_dir / latest_scan_id.group(1)
            if scan_folder.exists():
                logger.info(f"Saving scan folder {scan_folder} as an artifact.")
                dn.log_artifact(scan_folder)

        logger.success("BBOT scan completed.")

        return output

    @rg.tool_method(catch=True)
    async def query(
        self, cypher: str, params: dict[str, t.Any] | None = None
    ) -> list[dict[str, t.Any]]:
        """
        Execute custom Cypher queries for advanced analysis of reconnaissance data.

        Cypher is Neo4j's query language, similar to SQL but designed for graph data.
        Use this for complex queries that the specific tools don't cover.

        Args:
            cypher_query: The Cypher query to execute.
            params: Optional parameters to safely inject values (prevents injection).
                    Available fields: domain, ip, port, severity, name, label, tag, limit.

        Returns:
            Query results as a list of dictionaries.

        Common Query Patterns:

        1. FINDING SPECIFIC DOMAINS:
            - API subdomains: MATCH (n:DNS_NAME) WHERE n.name =~ '.*api.*\\.example\\.com' RETURN n
            - Specific pattern: MATCH (n:DNS_NAME) WHERE n.name =~ 'api\\.cp[0-9]+\\.dyson\\.com' RETURN n
            - Contains string: MATCH (n:DNS_NAME) WHERE n.name CONTAINS 'staging' RETURN n
            - Multiple domains: MATCH (n:DNS_NAME) WHERE n.name ENDS WITH '.com' OR n.name ENDS WITH '.net' RETURN n
            - By tag: MATCH (n:DNS_NAME) WHERE 'api-endpoint' IN n.tags RETURN n
            - Limit results: MATCH (n:DNS_NAME) WHERE n.name CONTAINS 'api' RETURN n LIMIT 10

        2. INFRASTRUCTURE MAPPING:
            - DNS to IP: MATCH (d:DNS_NAME)-[:RESOLVES_TO]->(ip:IP_ADDRESS) RETURN d.name, ip.address
            - Find all IPs for domain: MATCH (d:DNS_NAME {name: $domain})-[:RESOLVES_TO]->(ip) RETURN ip
            - Reverse DNS: MATCH (ip:IP_ADDRESS {address: $ip})<-[:RESOLVES_TO]-(d) RETURN d
            - Shared hosting: MATCH (ip:IP_ADDRESS)<-[:RESOLVES_TO]-(d:DNS_NAME) WITH ip, count(d) as cnt WHERE cnt > 1 RETURN ip, cnt

        3. SERVICE DISCOVERY:
            - Web services: MATCH (n:URL) WHERE n.status_code >= 200 AND n.status_code < 300 RETURN n
            - API endpoints: MATCH (n:URL) WHERE n.name CONTAINS '/api/' OR n.name CONTAINS '/v1/' RETURN n
            - Admin panels: MATCH (n:URL) WHERE n.name =~ '.*(admin|panel|dashboard|console).*' RETURN n
            - Specific ports: MATCH (p:OPEN_TCP_PORT) WHERE p.port IN [3306, 5432, 27017] RETURN p
            - Services by port: MATCH (ip:IP_ADDRESS)-[:HAS_PORT]->(p:OPEN_TCP_PORT {port: 443}) RETURN ip, p

        4. SECURITY ANALYSIS:
            - Critical findings: MATCH (f:FINDING) WHERE f.severity IN ['critical', 'high'] RETURN f
            - Exposed databases: MATCH (p:OPEN_TCP_PORT) WHERE p.port IN [3306, 5432, 6379, 27017, 9200] AND p.service CONTAINS 'mysql' OR p.service CONTAINS 'postgres' RETURN p
            - Public buckets: MATCH (n:STORAGE_BUCKET) WHERE n.public = true RETURN n
            - Authentication issues: MATCH (f:FINDING) WHERE f.description CONTAINS 'auth' OR f.description CONTAINS 'login' RETURN f

        5. PATH ANALYSIS:
            - Connection paths: MATCH p=(d:DNS_NAME)-[*1..3]-(f:FINDING) RETURN p
            - Shortest path: MATCH p=shortestPath((n1:DNS_NAME {name: $start})-[*]-(n2:DNS_NAME {name: $end})) RETURN p
            - All relationships: MATCH (n {name: $name})-[r]-(m) RETURN n, r, m

        6. AGGREGATION QUERIES:
            - Count by type: MATCH (n) RETURN labels(n)[0] as type, count(n) as count ORDER BY count DESC
            - Domains per IP: MATCH (ip:IP_ADDRESS)<-[:RESOLVES_TO]-(d) RETURN ip.address, collect(d.name) as domains
            - Top ports: MATCH (p:OPEN_TCP_PORT) RETURN p.port, count(p) as cnt ORDER BY cnt DESC LIMIT 10
            - Finding summary: MATCH (f:FINDING) RETURN f.severity, count(f) as count GROUP BY f.severity

        7. COMPLEX FILTERS:
            - Date ranges: MATCH (n) WHERE n.created_at > datetime('2024-01-01') RETURN n
            - Multiple conditions: MATCH (n:URL) WHERE n.status_code = 200 AND (n.title CONTAINS 'Admin' OR n.title CONTAINS 'Login') RETURN n
            - Regex matching: MATCH (n:DNS_NAME) WHERE n.name =~ '(?i).*dev.*|.*test.*|.*staging.*' RETURN n
            - NOT conditions: MATCH (n:URL) WHERE NOT n.status_code IN [404, 403, 401] RETURN n

        8. ADVANCED PATTERNS:
            - Scan-specific data: MATCH (s:SCAN {name: $scan_name})-[*]-(n) RETURN DISTINCT n
            - Cross-reference: MATCH (d1:DNS_NAME)-[:RESOLVES_TO]->(ip)<-[:RESOLVES_TO]-(d2:DNS_NAME) WHERE d1 <> d2 RETURN d1, ip, d2
            - Technology stack: MATCH (n:TECHNOLOGY)-[:USED_BY]->(u:URL) RETURN n.name, collect(u.name)
            - Email discovery: MATCH (e:EMAIL_ADDRESS) WHERE e.address ENDS WITH $domain RETURN e

        9. QUICK LOOKUPS (Replacing removed functions):
            - Get specific DNS: MATCH (n:DNS_NAME {name: 'api.example.com'}) RETURN n
            - Get URL by path: MATCH (n:URL) WHERE n.name ENDS WITH '/login' RETURN n LIMIT 10
            - Get port on IP: MATCH (i:IP_ADDRESS {address: '192.168.1.1'})-[:HAS_PORT]->(p) RETURN p
            - Get IP info: MATCH (n:IP_ADDRESS {address: $ip}) RETURN n
            - List DNS names: MATCH (n:DNS_NAME) RETURN n.name ORDER BY n.name LIMIT 20
            - List open ports: MATCH (p:OPEN_TCP_PORT) RETURN DISTINCT p.port ORDER BY p.port

        Security Notes:
            - ALWAYS use parameters ($param) for user input to prevent injection
            - Use regex escaping (\\) for special characters in patterns
            - Limit results to prevent overwhelming responses
            - Start with small limits (10-20) and increase if needed

        Example Usage:
            query('MATCH (n:DNS_NAME) WHERE n.name =~ ".*api.*" RETURN n LIMIT 20')
            query('MATCH (n:FINDING {severity: $sev}) RETURN n', {'sev': 'critical'})
            query('MATCH (d:DNS_NAME {name: $domain})-[:RESOLVES_TO]->(ip) RETURN ip', {'domain': 'example.com'})
            query('MATCH (n:DNS_NAME) WHERE n.name =~ "api\\.cp[0-9]+\\.dyson\\.com" RETURN n')
        """
        return await super().query(cypher, params)

    @rg.tool_method(catch=True)
    async def get_scans(
        self,
        summary: bool = True,  # noqa: FBT001, FBT002
        scope_distance: int = 0,
        tags: list[str] | None = None,
    ) -> list[dict[str, t.Any]]:
        """
        Retrieve BBOT scan metadata and configuration information.

        Scans are the top-level entity containing information about reconnaissance runs,
        including targets, modules used, and timing information.

        Args:
            summary: Return condensed output suitable for LLMs (default: True).
                    Truncates long strings and lists for readability.
            tags: Filter by scan tags (e.g., ['production', 'web-app']).
                Only returns scans containing ALL specified tags.
            scope_distance: Filter by scope distance from original targets.
                        0 = direct targets, 1 = one hop away, etc.

        Returns:
            List of scan records containing scan_id, target, status, start/end times,
            modules used, and configuration details.

        Example:
            get_scans(tags=['production']) - Get all production scans
            get_scans(scope_distance=0) - Get only direct target scans
        """
        scope_distance = scope_distance or 0
        scans = await self.get_nodes(
            label="SCAN",
            filters={"scope_distance": scope_distance, **({"tags": tags} if tags else {})},
        )
        return [_summarize(scan) if summary else scan for scan in scans]

    @rg.tool_method(catch=True)
    async def get_findings(
        self,
        summary: bool = True,  # noqa: FBT001, FBT002
        scope_distance: int = 0,
        tags: list[str] | None = None,
    ) -> list[dict[str, t.Any]]:
        """Retrieve security findings and vulnerabilities discovered during scans.

        Findings represent potential security issues, misconfigurations, exposed
        credentials, vulnerable services, and other security-relevant discoveries.

        Args:
            summary: Return condensed output suitable for LLMs (default: True).
                    Truncates long strings and lists for readability.
            tags: Filter by tags (e.g., ['critical', 'authentication', 'exposure']).
                Only returns findings containing ALL specified tags.
            scope_distance: Filter by scope distance from original targets.
                        0 = findings on direct targets.

        Returns:
            List of finding records containing type, severity, description,
            affected resource, evidence, and remediation suggestions.

        Example:
            get_findings(tags=['critical']) - Get critical severity findings
            get_findings(tags=['authentication']) - Find auth-related issues
        """
        findings = await self.get_nodes(
            label="FINDING",
            filters={"scope_distance": scope_distance, **({"tags": tags} if tags else {})},
        )
        return [_summarize(finding) if summary else finding for finding in findings]

    @rg.tool_method(catch=True)
    async def get_screenshot(
        self, uuid: str | None = None, url: str | None = None
    ) -> rg.ContentImageUrl | None:
        """
        Retrieves the local file path and original URL for a WEBSCREENSHOT.

        You can identify a screenshot either by its 'uuid' (found via explore_nodes)
        or by the original URL that was screenshotted.

        Args:
            uuid: The 'uuid' of the WEBSCREENSHOT node.
            url: The URL to search for a screenshot of (e.g., 'https://example.com/login').

        Returns:
            The screenshot image
        """
        if not uuid and not url:
            raise ValueError("Either 'uuid' or 'url' must be provided to get a screenshot.")

        # If a URL is provided, we first need to find the corresponding screenshot uuid
        if url and not uuid:
            logger.debug(f"Searching for screenshot by URL: {url}")

            nodes = await self.explore_nodes(
                label="WEBSCREENSHOT", property_filter=f"url CONTAINS '{url}'", limit=1
            )
            if nodes:
                uuid = nodes[0].get("node", {}).get("uuid")
                if not uuid:
                    logger.warning(f"No screenshot found for URL '{url}'.")
                    return None
            else:
                logger.warning(f"No screenshot found for URL '{url}'.")
                return None

        logger.debug(f"Retrieving screenshot data for uuid: {uuid}")

        cypher = """
        MATCH (w:WEBSCREENSHOT {uuid: $uuid})
        MATCH (s:SCAN {id: w.scan})
        RETURN w.data AS web_data, s.data AS scan_data
        """
        result = await self.query(cypher, params={"uuid": uuid})
        if not result:
            return None

        scan_data = _parse_serialized_dict(result[0].get("scan_data", ""))
        web_data = _parse_serialized_dict(result[0].get("web_data", ""))

        scan_name = str(scan_data.get("name"))
        relative_path = str(web_data.get("path"))
        original_url = str(web_data.get("url"))

        if not all([scan_name, relative_path, original_url]):
            logger.error("Screenshot or scan data is missing required fields (name, path, url).")
            return None

        full_path = self.bbot_home / "scans" / scan_name / relative_path

        if not full_path.exists():
            logger.error(f"Screenshot file not found at expected path: {full_path}")
            return None

        dn.log_output("screenshot", dn.Image(full_path))
        dn.log_output("screenshot_metadata", result[0])

        return rg.ContentImageUrl.from_file(full_path)
