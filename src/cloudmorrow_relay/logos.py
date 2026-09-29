"""Checking a logo before the landing page shows it.

PNG, JPEG or SVG, at most 256 KiB, and the bytes must be what the content
type says. PNG and JPEG are taken on their signature: the page shows them
as an `<img>`, and a browser does nothing with an image but draw it.

SVG is a document and could carry script, so it is refused unless it is
plainly a picture: well-formed XML with an `<svg>` root, no DOCTYPE or
entities, no `<script>`, `<foreignObject>` or event handlers, and no links
anywhere but inside itself (`#id`) or to an embedded PNG/JPEG. It is
refused rather than cleaned: the owner sees why and can export it again.
The landing page serves it with a policy that forbids everything besides
(landing.py), so a mistake here is still not a hole.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

MAX_BYTES = 256 * 1024

TYPES = {
    "image/png": "image/png",
    "image/jpeg": "image/jpeg",
    "image/jpg": "image/jpeg",
    "image/svg+xml": "image/svg+xml",
}

FORBIDDEN_TAGS = {"script", "foreignobject", "iframe", "embed", "object", "handler", "listener"}
LINK_ATTRS = {"href", "src"}
SAFE_LINK = re.compile(r"^(#[A-Za-z0-9_.:-]*|data:image/(png|jpeg);base64,[A-Za-z0-9+/=\s]*)$")
URL_IN_STYLE = re.compile(r"url\(\s*['\"]?\s*(?!#)", re.I)


class LogoError(ValueError):
    pass


def _local(name: str) -> str:
    return name.rsplit("}", 1)[-1].lower()


def check(content_type: str, data: bytes) -> str:
    """The content type to store the logo under, or LogoError with a
    sentence saying what is wrong.
    """
    kind = TYPES.get((content_type or "").split(";")[0].strip().lower())
    if kind is None:
        raise LogoError("A logo is a PNG, SVG or JPEG image.")
    if not data:
        raise LogoError("The logo is empty.")
    if len(data) > MAX_BYTES:
        raise LogoError("A logo is at most 256 KiB.")
    if kind == "image/png" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise LogoError("That is not a PNG image.")
    if kind == "image/jpeg" and not data.startswith(b"\xff\xd8\xff"):
        raise LogoError("That is not a JPEG image.")
    if kind == "image/svg+xml":
        _check_svg(data)
    return kind


def _check_svg(data: bytes) -> None:
    lower = data.lower()
    if b"<!doctype" in lower or b"<!entity" in lower:
        raise LogoError("An SVG logo cannot have a DOCTYPE or entities.")
    if b"<?xml-stylesheet" in lower:
        raise LogoError("An SVG logo cannot load anything from elsewhere.")
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raise LogoError("That SVG is not well-formed XML.") from None
    if _local(root.tag) != "svg":
        raise LogoError("That is not an SVG image.")
    for element in root.iter():
        tag = _local(element.tag) if isinstance(element.tag, str) else ""
        if tag in FORBIDDEN_TAGS:
            raise LogoError(f"An SVG logo cannot have <{tag}> in it.")
        if tag == "style" and element.text and (URL_IN_STYLE.search(element.text) or "@import" in element.text):
            raise LogoError("An SVG logo cannot load anything from elsewhere.")
        for name, value in element.attrib.items():
            attr = _local(name)
            if attr.startswith("on"):
                raise LogoError("An SVG logo cannot have event handlers in it.")
            if attr in LINK_ATTRS and not SAFE_LINK.match(value.strip()):
                raise LogoError("An SVG logo cannot link to anything outside itself.")
            if URL_IN_STYLE.search(value):
                raise LogoError("An SVG logo cannot load anything from elsewhere.")
