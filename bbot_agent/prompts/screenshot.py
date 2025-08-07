import typing as t

import rigging as rg


class Analysis(rg.Model):
    priority: t.Literal["low", "medium", "high", "critical"] = rg.element(
        description="Triage priority for human follow-up - one of `low`, `medium`, `high`, or `critical`.",
        examples=["medium"],
    )
    elements: rg.model.CommaDelimitedAnswer = rg.element(
        "elements",
        description="A comma-separated list of specific elements within the screenshot that are noteworthy or require further examination.",
        examples=["admin panel, error message, legacy"],
    )
    summary: str = rg.element(
        description="A markdown summary explaining *why* the screenshot is interesting and what a human should investigate next."
    )


@rg.prompt
async def analyze_screenshot(metadata: t.Any | None = None) -> Analysis:  # type: ignore[empty-body]
    """
    Your task is to triage web application screenshots to identify high-value targets for manual investigation.

    Instead of focusing only on direct vulnerabilities, identify "interesting assets" that look the most valuable for human follow-up. Analyze each screenshot and prioritize it based on the potential for deeper access or information discovery.

    {% if metadata %}
    <metadata>
    {{ metadata }}
    </metadata>
    {% endif %}
    ---

    ## Guiding Principles for Triage

    1. **Intent is Vulnerability Discovery**: The ultimate goal of the follow-up is to find and exploit vulnerabilities. A screenshot is "interesting" if it suggests a high likelihood of success for a human tester.
    2. **Structure Over Content**: The general content of a page (e.g., marketing text, blog posts) is less relevant. Focus on the page's structure, components, and apparent function. A simple login form is more interesting than a complex "About Us" page.
    3. **Appearance and Style as Clues**: Pay attention to the visual design. Does it look like a polished, public-facing page or a bare-bones internal tool? Assets that appear to be made for internal or technical users often have weaker security controls and are higher priority.
    4. **Prioritize Human Interaction**: Look for pages designed for human input and interaction. Forms, dashboards, and control panels are far more valuable than static pages because they represent a direct interface with the application's backend logic.

    ## Asset Priorities

    1. **High-Value Portals**:
        - Look for administrative interfaces, control panels, or backend management systems.
        - Identify any login forms, especially those that specify "admin," "staff," or "internal." These are critical targets.
    2. **Developer and API Artifacts**:
        - Scan for API documentation pages (e.g., Swagger, OpenAPI, Redoc).
        - Note any visible developer consoles, GraphQL interfaces, or links to code repositories.
    3. **Complex Functionality and Data Entry**:
        - Identify complex forms that handle sensitive data (e.g., user settings, financial information).
        - Flag any file upload functionality, as this is a common area for exploitation.
        - Note powerful search functions, which might be leveraged for advanced attacks.
    4. **Information-Rich Pages and Dashboards**:
        - Look for dashboards, reporting interfaces, or pages displaying large tables of data that might contain user information or internal metrics.
        - Identify any pages that look like internal tools not meant for public viewing.
    5. **Technology and Infrastructure Clues**:
        - Note any explicit server information, software names, or version numbers (e.g., "Apache/2.4.18," "PHP 7.4," "WordPress 6.0"). This information is valuable for targeted testing.
    6. **Debug Information and Errors**:
        - Flag any pages that display verbose error messages, stack traces, or other debug information. These can reveal underlying paths, libraries, and configurations.
    7. **Legacy Assets**:
        - Identify any pages that look outdated, legacy, or otherwise built on old technologies.
        - Look for references to old technologies or frameworks that might be exploitable.
    """
