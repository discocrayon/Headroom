"""
Keep README.md's check table in step with the registry.

The retired single-file specification listed 7 of the 15 checks registered
when it was removed; nothing had checked it. README.md names every check in
one table, and this test fails naming any registered check the table omits.
The two counts in the prose around the table are checked against the
registry the same way.

README.md also embeds `documentation/images/placement.svg`, a render of the
console block in `documentation/EXAMPLES.md`; the first hand-copied version
of that image drifted on its first day, so this test compares the two. When
they diverge, the image is what changes: regenerate it with
documentation/images/generate_placement_svg.py rather than editing this test.

`documentation/images/hierarchy.svg` draws the organization that run scanned,
with one policy attached at the root and one at two OUs. Its edges carry the
node ids they join, so this test rebuilds the tree from the image and compares
it to `test_environment/accounts.tf` and `organizational_units.tf`, and
compares the attachments to what the root module in EXAMPLES.md says about
each check. Regenerate it with documentation/images/generate_hierarchy_svg.py.
"""

import re
import xml.etree.ElementTree
from pathlib import Path

from headroom.checks.registry import get_check_type_map

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent

_SVG_NAMESPACE = "http://www.w3.org/2000/svg"

# The SVG wraps a long `Reasoning:` line once and hangs the remainder under the
# text after its label. Only those three lines exceed the render width.
_CONTINUATION_INDENT = " " * len("  Reasoning: ")
_HEADING = "## Console output"
_FENCE = re.compile(r"^```[a-z]*\n(.*?)^```", re.MULTILINE | re.DOTALL)
_IMAGES = REPOSITORY_ROOT / "documentation" / "images"
_TEST_ENVIRONMENT = REPOSITORY_ROOT / "test_environment"
_ROOT_MODULE_HEADING = "**Shape of**: `{scps_dir}/root_scps.tf`"
_ROOT_MODULE_VARIABLE = re.compile(r"^\s*(deny_\w+)\s*=\s*(true|false)$")
_ENFORCED_BELOW = re.compile(r"Enforced below at (.+?); blocked elsewhere by \d+ of \d+ analyzed accounts \((.+?)\)")
# One Organizations resource in the test environment: its display name and
# the reference its `parent_id` holds, either the root or an OU resource.
_ORGANIZATIONS_RESOURCE = re.compile(
    r'resource "aws_organizations_(?:account|organizational_unit)" "(\w+)" \{\n'
    r'  name\s*=\s*"([^"]+)"\n'
    r'(?:.*\n)*?'
    r'  parent_id\s*=\s*(\S+)\n',
)
_OU_REFERENCE = re.compile(r"aws_organizations_organizational_unit\.(\w+)\.id")
_ROOT_LABEL = "Organization root"


def test_readme_links_every_registered_check_to_its_specification() -> None:
    readme_text = (REPOSITORY_ROOT / "README.md").read_text()

    missing = [
        name
        for name, check_type in get_check_type_map().items()
        if f"](spec/checks/{check_type}/{name}.md)" not in readme_text
    ]

    assert missing == []


def test_placement_render_matches_the_console_example() -> None:
    svg_root = xml.etree.ElementTree.parse(
        REPOSITORY_ROOT / "documentation" / "images" / "placement.svg",
    ).getroot()

    # "g/text" reaches the text elements one level down: the children of the
    # one <g> element, in document order. It excludes the title-bar label,
    # which sits outside <g>.
    lines: list[str] = []
    for text_element in svg_root.findall(f"{{{_SVG_NAMESPACE}}}g/{{{_SVG_NAMESPACE}}}text"):
        content = "".join(text_element.itertext())
        if content.startswith(_CONTINUATION_INDENT):
            lines[-1] = f"{lines[-1]} {content.removeprefix(_CONTINUATION_INDENT)}"
            continue
        lines.append(content)

    examples_text = (REPOSITORY_ROOT / "documentation" / "EXAMPLES.md").read_text()
    after_heading = examples_text.split(_HEADING, 1)[1]
    console_block: str = _FENCE.findall(after_heading)[0]

    assert lines == [line for line in console_block.splitlines() if line]


def _hierarchy_render() -> tuple[dict[str, str], dict[str, str], list[tuple[str, str, str]]]:
    """
    Return the node labels and classes by id, and every edge as
    (class, from id, to id), read back from hierarchy.svg.
    """
    svg_root = xml.etree.ElementTree.parse(_IMAGES / "hierarchy.svg").getroot()
    labels: dict[str, str] = {}
    classes: dict[str, str] = {}
    for node in svg_root.iterfind(f".//{{{_SVG_NAMESPACE}}}g[@id]"):
        node_id = node.get("id", "")
        name = node.find(f"{{{_SVG_NAMESPACE}}}text[@class='name']")
        assert name is not None and name.text is not None, node_id
        labels[node_id] = name.text
        classes[node_id] = node.get("class", "")
    edges = [
        (line.get("class", ""), line.get("data-from", ""), line.get("data-to", ""))
        for line in svg_root.iterfind(f".//{{{_SVG_NAMESPACE}}}line[@data-from]")
    ]
    return labels, classes, edges


def _test_environment_topology() -> set[tuple[str, str]]:
    """
    Return every (parent label, child label) the test environment declares,
    labelled the way the image labels them.
    """
    resources = [
        match
        for filename in ("organizational_units.tf", "accounts.tf")
        for match in _ORGANIZATIONS_RESOURCE.findall((_TEST_ENVIRONMENT / filename).read_text())
    ]
    ou_label_by_resource = {
        resource_name: f"OU {name}"
        for resource_name, name, parent in resources
        if not _OU_REFERENCE.fullmatch(parent)
    }
    topology: set[tuple[str, str]] = set()
    for resource_name, name, parent in resources:
        ou = _OU_REFERENCE.fullmatch(parent)
        if ou is None:
            topology.add((_ROOT_LABEL, ou_label_by_resource[resource_name]))
            continue
        topology.add((ou_label_by_resource[ou.group(1)], name))
    return topology


def _example_root_module() -> dict[str, tuple[str, str]]:
    """
    Return each variable of the example root module in EXAMPLES.md as
    (value, the comment above it joined into one line).
    """
    examples_text = (REPOSITORY_ROOT / "documentation" / "EXAMPLES.md").read_text()
    block: str = _FENCE.findall(examples_text.split(_ROOT_MODULE_HEADING, 1)[1])[0]
    variables: dict[str, tuple[str, str]] = {}
    comment: list[str] = []
    for line in block.splitlines():
        if line.strip().startswith("#"):
            comment.append(line.strip().removeprefix("#").strip())
            continue
        variable = _ROOT_MODULE_VARIABLE.match(line)
        if variable is not None:
            variables[variable.group(1)] = (variable.group(2), " ".join(comment))
        comment = []
    return variables


def test_hierarchy_render_draws_the_test_environment_topology() -> None:
    labels, _, edges = _hierarchy_render()

    drawn = {(labels[parent], labels[child]) for cls, parent, child in edges if cls == "contains"}

    assert drawn == _test_environment_topology()


def test_hierarchy_render_agrees_with_the_example_root_module() -> None:
    labels, classes, edges = _hierarchy_render()
    root_module = _example_root_module()
    violating = {labels[node] for node, cls in classes.items() if "violating" in cls}

    attached: dict[str, set[str]] = {}
    for cls, policy, target in edges:
        if cls != "attached":
            continue
        attached.setdefault(labels[policy], set()).add(labels[target])

    assert attached
    assert set(attached) <= set(get_check_type_map())
    for check, targets in attached.items():
        value, comment = root_module[check]
        if targets == {_ROOT_LABEL}:
            assert value == "true", check
            continue
        enforced = _ENFORCED_BELOW.search(comment)
        assert enforced is not None, check
        assert targets == set(enforced.group(1).split(", ")), check
        assert violating == set(enforced.group(2).split(", ")), check


def test_readme_states_the_registry_counts() -> None:
    readme_text = (REPOSITORY_ROOT / "README.md").read_text()
    check_types = list(get_check_type_map().values())

    assert f"{len(check_types)} checks ship today" in readme_text
    assert (
        f"The first {check_types.count('scps')} are SCPs, the last "
        f"{check_types.count('rcps')} RCPs"
        in readme_text
    )
