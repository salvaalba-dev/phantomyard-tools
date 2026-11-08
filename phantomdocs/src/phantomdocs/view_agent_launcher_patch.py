"""Prepare an opt-in agent-aware variant of the pinned viewer launcher.

The returned bytes are inactive. The operator must protect the configuration,
install the matching reader candidate, and separately approve deployment.
"""

import ast
import hashlib

SOURCE_SHA256 = "f449aaf8ecc259a645e08c9c53ff34188255f766c76b9248e94fa3f323ac2883"
FIELDS_ANCHOR = "(FIELDS | {'additional_issuers', 'reviewed_knowledge'})"
RETURN_ANCHOR = "    return result\n\n\ndef issuer_routes(config):\n"
BUILD_ANCHOR = (
    "    options = {'additional_issuers': config['additional_issuers']} "
    "if 'additional_issuers' in config else {}\n"
)


def patch_launcher(source):
    """Return a launcher candidate that accepts trusted agent route names."""
    if (
        not isinstance(source, bytes)
        or hashlib.sha256(source).hexdigest() != SOURCE_SHA256
    ):
        raise ValueError("Unsupported PhantomView launcher revision")
    text = source.decode("utf-8")
    newline = "\r\n" if "\r\n" in text else "\n"
    text = text.replace("\r\n", "\n")
    for anchor in (FIELDS_ANCHOR, RETURN_ANCHOR, BUILD_ANCHOR):
        if text.count(anchor) != 1:
            raise ValueError("Launcher composition changed")
    text = text.replace(
        FIELDS_ANCHOR,
        "(FIELDS | {'additional_issuers', 'reviewed_knowledge', 'agent_actors'})",
        1,
    )
    text = text.replace(
        RETURN_ANCHOR,
        "    if 'agent_actors' in value:\n"
        "        actors = value['agent_actors']\n"
        "        if (not isinstance(actors, list)\n"
        "                or not all(isinstance(item, str) for item in actors)\n"
        "                or len(actors) != len(set(actors))):\n"
        "            raise ValueError('Agent actors must be a unique list')\n"
        "        routes = [result['actor'], *(route['actor'] for route in result.get('additional_issuers', []))]\n"
        "        if not set(actors) <= set(routes):\n"
        "            raise ValueError('Agent actor has no issuer route')\n"
        "        result['agent_actors'] = list(actors)\n" + RETURN_ANCHOR,
        1,
    )
    text = text.replace(
        BUILD_ANCHOR,
        BUILD_ANCHOR + "    if 'agent_actors' in config:\n"
        "        options['agent_actors'] = config['agent_actors']\n",
        1,
    )
    ast.parse(text)
    return text.replace("\n", newline).encode("utf-8")
