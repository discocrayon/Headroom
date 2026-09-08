"""
Render hierarchy.svg, the organization diagram at the top of README.md.

Run from the repository root:

    .tox/py313/bin/python documentation/images/generate_hierarchy_svg.py

The diagram draws the test environment's organization - one root, three OUs,
four accounts - and the two attachments the example run in
documentation/EXAMPLES.md makes: deny_ec2_ami_owner at the root, and
deny_ec2_imds_v1 at the two OUs whose accounts are clean, because the third OU
holds the one account with an IMDSv1 instance. The image replaced a Mermaid
block: GitHub overlays a pan-and-zoom toolbar on every Mermaid diagram, and its
mobile app does not render them at all.

Every node is a <g> carrying its id and a <text class="name">, and every edge
is a <line> carrying `data-from` and `data-to`, so tests/test_readme.py can
rebuild the tree and the attachments from the image and compare them with
test_environment/ and EXAMPLES.md. Re-run this script rather than editing the
image or the test. Text widths cannot be measured here, so each box is sized
by hand with room to spare for the widest common system font.
"""

from pathlib import Path
from typing import NamedTuple
from xml.sax.saxutils import escape

OUTPUT = Path(__file__).with_name("hierarchy.svg")

TITLE = (
    "Headroom attaches deny_ec2_ami_owner at the organization root and "
    "deny_ec2_imds_v1 at the two OUs with no violating account"
)

WIDTH = 880
HEIGHT = 360
BOX_HEIGHT = 40
DETAIL_BOX_HEIGHT = 56
CHAMFER = 12
PAD_X = 10
FONT_SIZE = 13
DETAIL_FONT_SIZE = 11
EDGE_LABEL_FONT_SIZE = 11
SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

TEXT = "#111111"
EDGE = "#6e7781"
ATTACHED = "#2f6fd0"
VIOLATION = "#c0392b"
# fill, stroke
STYLES = {
    "container": ("#e8edf3", "#57606a"),
    "account": ("#f6f8fa", "#8c959f"),
    "violating": ("#fde2e2", VIOLATION),
    "policy": ("#e3f2fd", "#1565c0"),
}


class Node(NamedTuple):
    label: str
    kind: str
    cx: int
    cy: int
    width: int
    mark: str = ""
    detail: str = ""


NODES = {
    "ami": Node("deny_ec2_ami_owner", "policy", 150, 48, 190),
    "root": Node("Organization root", "container", 440, 48, 190),
    "ss": Node("OU shared_services", "container", 100, 180, 160),
    "hva": Node("OU high_value_assets", "container", 352, 180, 165),
    "imds": Node("deny_ec2_imds_v1", "policy", 567, 180, 160),
    "acq": Node("OU acme_acquisition", "container", 779, 180, 160),
    "sfb": Node("shared-foo-bar", "violating", 100, 312, 160, mark="❌", detail="one IMDSv1 instance"),
    "fk": Node("fort-knox", "account", 266, 312, 110, mark="✅"),
    "st": Node("security-tooling", "account", 413, 312, 160, mark="✅"),
    "ac": Node("acme-co", "account", 779, 312, 120, mark="✅"),
}
CONTAINS = (
    ("root", "ss"),
    ("root", "hva"),
    ("root", "acq"),
    ("hva", "fk"),
    ("hva", "st"),
    ("ss", "sfb"),
    ("acq", "ac"),
)
ATTACHMENTS = (
    ("ami", "root"),
    ("imds", "hva"),
    ("imds", "acq"),
)


def height(node: Node) -> int:
    return DETAIL_BOX_HEIGHT if node.detail else BOX_HEIGHT


def shape(node: Node) -> str:
    fill, stroke = STYLES[node.kind]
    left = node.cx - node.width // 2
    top = node.cy - height(node) // 2
    if node.kind != "policy":
        return f'    <rect x="{left}" y="{top}" width="{node.width}" height="{height(node)}" rx="6" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'
    right = left + node.width
    bottom = top + height(node)
    points = (
        f"{left + CHAMFER},{top} {right - CHAMFER},{top} {right},{node.cy} "
        f"{right - CHAMFER},{bottom} {left + CHAMFER},{bottom} {left},{node.cy}"
    )
    return f'    <polygon points="{points}" fill="{fill}" stroke="{stroke}" stroke-width="1.5"/>'


def text(node: Node) -> list[str]:
    left = node.cx - node.width // 2
    right = left + node.width
    baseline = node.cy + 5 - (8 if node.detail else 0)
    if node.kind == "policy":
        return [f'    <text class="name" x="{node.cx}" y="{baseline}" text-anchor="middle" font-family="{MONO}" font-size="{FONT_SIZE}" fill="{TEXT}">{escape(node.label)}</text>']
    weight = ' font-weight="bold"' if node.kind == "container" else ""
    anchor = f'x="{left + PAD_X}"' if node.mark else f'x="{node.cx}" text-anchor="middle"'
    lines = [f'    <text class="name" {anchor} y="{baseline}" font-family="{SANS}" font-size="{FONT_SIZE}"{weight} fill="{TEXT}">{escape(node.label)}</text>']
    if node.mark:
        lines.append(f'    <text class="mark" x="{right - PAD_X}" y="{baseline}" text-anchor="end" font-size="{FONT_SIZE}">{node.mark}</text>')
    if node.detail:
        lines.append(f'    <text class="detail" x="{left + PAD_X}" y="{baseline + 17}" font-family="{SANS}" font-size="{DETAIL_FONT_SIZE}" fill="{VIOLATION}">{escape(node.detail)}</text>')
    return lines


def contains_edge(parent_id: str, child_id: str) -> str:
    parent, child = NODES[parent_id], NODES[child_id]
    return (
        f'    <line class="contains" data-from="{parent_id}" data-to="{child_id}" '
        f'x1="{parent.cx}" y1="{parent.cy + height(parent) // 2}" x2="{child.cx}" y2="{child.cy - height(child) // 2}" '
        f'stroke="{EDGE}" stroke-width="1.5" marker-end="url(#contains-arrow)"/>'
    )


def attached_edge(policy_id: str, target_id: str) -> list[str]:
    """
    Draw the dotted arrow from a policy to the node it is attached to, with
    its label above the midpoint. The pairs are laid out side by side, so
    the arrow always runs horizontally between the two shapes' near edges.
    """
    policy, target = NODES[policy_id], NODES[target_id]
    if policy.cx < target.cx:
        x1, x2 = policy.cx + policy.width // 2, target.cx - target.width // 2
    else:
        x1, x2 = policy.cx - policy.width // 2, target.cx + target.width // 2
    return [
        f'    <line class="attached" data-from="{policy_id}" data-to="{target_id}" '
        f'x1="{x1}" y1="{policy.cy}" x2="{x2}" y2="{policy.cy}" '
        f'stroke="{ATTACHED}" stroke-width="1.5" stroke-dasharray="4 3" marker-end="url(#attached-arrow)"/>',
        f'    <text x="{(x1 + x2) // 2}" y="{policy.cy - 7}" text-anchor="middle" font-family="{SANS}" font-size="{EDGE_LABEL_FONT_SIZE}" fill="{ATTACHED}">attached</text>',
    ]


def render() -> str:
    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" aria-labelledby="hierarchy-title">',
        f'  <title id="hierarchy-title">{TITLE}</title>',
        "  <defs>",
        f'    <marker id="contains-arrow" markerWidth="8" markerHeight="8" refX="8" refY="4" orient="auto" markerUnits="userSpaceOnUse"><path d="M0 0L8 4L0 8z" fill="{EDGE}"/></marker>',
        f'    <marker id="attached-arrow" markerWidth="8" markerHeight="8" refX="8" refY="4" orient="auto" markerUnits="userSpaceOnUse"><path d="M0 0L8 4L0 8z" fill="{ATTACHED}"/></marker>',
        "  </defs>",
        '  <g class="edges">',
    ]
    svg.extend(contains_edge(parent, child) for parent, child in CONTAINS)
    for policy, target in ATTACHMENTS:
        svg.extend(attached_edge(policy, target))
    svg.append("  </g>")
    for node_id, node in NODES.items():
        svg.append(f'  <g id="{node_id}" class="node {node.kind}">')
        svg.append(shape(node))
        svg.extend(text(node))
        svg.append("  </g>")
    svg.append("</svg>")
    return "\n".join(svg) + "\n"


def main() -> None:
    OUTPUT.write_text(render())
    print(OUTPUT)


if __name__ == "__main__":
    main()
