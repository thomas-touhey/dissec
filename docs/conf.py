"""Configuration file for the Sphinx documentation builder.

For the full list of built-in configuration values, see the documentation:
https://www.sphinx-doc.org/en/master/usage/configuration.html
"""

from __future__ import annotations

import sys
from pathlib import Path

from toml import load as load_toml

# Add the module path.
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.append(str(Path(__file__).parent / "_ext"))
pyproject_path = Path(__file__).parent.parent / "pyproject.toml"

with open(pyproject_path) as pyproject_file:
    version = load_toml(pyproject_file)["project"]["version"]

project = "dissec"
copyright = "2024, Thomas Touhey"
author = "Thomas Touhey"

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.doctest",
    "sphinx.ext.intersphinx",
    "sphinx.ext.todo",
    "sphinxcontrib.autodoc_pydantic",
    "dissec_autodoc",
]

templates_path: list[str] = []
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "furo"
html_static_path = ["_static"]
html_title = f"dissec {version}"
html_favicon = "_static/favicon.png"
html_logo = "_static/logo.svg"
html_use_index = False
html_copy_source = False
html_show_sourcelink = False
html_domain_indices = False
html_css_files = ["custom.css"]

intersphinx_mapping: dict[str, tuple[str, None]] = {
    "python": ("https://docs.python.org/3", None),
    "pydantic": ("https://docs.pydantic.dev/latest", None),
}

todo_include_todos = True

autodoc_typehints_format = "short"
autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "exclude-members": "model_config, model_fields, model_computed_fields, "
    + "model_post_init",
}
autodoc_member_order = "bysource"

autodoc_pydantic_model_show_config_summary = False
autodoc_pydantic_model_show_field_summary = False
autodoc_pydantic_model_show_json = False
