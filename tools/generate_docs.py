# Copyright 2026 UCID Foundation
#
# Licensed under the EUPL, Version 1.2 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Documentation generator for UCID library.

This tool generates API documentation from Python source code by
extracting docstrings and creating Markdown documentation files.

Usage:
    python tools/generate_docs.py [options]

Examples:
    # Generate all documentation
    python tools/generate_docs.py

    # Generate to specific directory
    python tools/generate_docs.py --output docs/api/

    # Generate for specific module
    python tools/generate_docs.py --module ucid.core.parser

Output Structure:
    docs/api/
    ├── index.md
    ├── core/
    │   ├── parser.md
    │   ├── validator.md
    │   └── models.md
    ├── contexts/
    │   └── ...
    └── api/
        └── ...
"""

from __future__ import annotations

import argparse
import importlib
import inspect
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Sequence


def get_module_members(module: Any) -> dict[str, list[tuple[str, Any]]]:
    """Get all public members of a module.

    Args:
        module: Module to inspect.

    Returns:
        Dictionary of member types to lists of (name, object) tuples.
    """
    members: dict[str, list[tuple[str, Any]]] = {
        "classes": [],
        "functions": [],
        "constants": [],
    }

    for name, obj in inspect.getmembers(module):
        # Skip private members
        if name.startswith("_"):
            continue

        # Skip imported members
        if hasattr(obj, "__module__") and obj.__module__ != module.__name__:
            continue

        if inspect.isclass(obj):
            members["classes"].append((name, obj))
        elif inspect.isfunction(obj):
            members["functions"].append((name, obj))
        elif not inspect.ismodule(obj):
            members["constants"].append((name, obj))

    return members


def format_signature(obj: Any) -> str:
    """Format function or class signature.

    Args:
        obj: Function or class to format.

    Returns:
        Formatted signature string.
    """
    try:
        sig = inspect.signature(obj)
        return str(sig)
    except (ValueError, TypeError):
        return "()"


def format_docstring(docstring: str | None) -> str:
    """Format docstring for Markdown.

    Args:
        docstring: Raw docstring.

    Returns:
        Formatted docstring.
    """
    if not docstring:
        return "*No documentation available.*"

    # Clean up indentation
    lines = docstring.strip().split("\n")
    if len(lines) > 1:
        # Find minimum indentation
        min_indent = float("inf")
        for line in lines[1:]:
            if line.strip():
                indent = len(line) - len(line.lstrip())
                min_indent = min(min_indent, indent)

        if min_indent < float("inf"):
            lines = [lines[0]] + [
                line[int(min_indent):] if line.strip() else ""
                for line in lines[1:]
            ]

    return "\n".join(lines)


def generate_class_doc(name: str, cls: type) -> str:
    """Generate documentation for a class.

    Args:
        name: Class name.
        cls: Class object.

    Returns:
        Markdown documentation.
    """
    lines = [
        f"### `class {name}`",
        "",
        f"```python",
        f"class {name}{format_signature(cls)}",
        "```",
        "",
        format_docstring(cls.__doc__),
        "",
    ]

    # Document methods
    methods = []
    for method_name, method in inspect.getmembers(cls, predicate=inspect.isfunction):
        if not method_name.startswith("_") or method_name in ("__init__", "__str__", "__repr__"):
            methods.append((method_name, method))

    if methods:
        lines.extend([
            "#### Methods",
            "",
        ])

        for method_name, method in methods:
            lines.extend([
                f"##### `{method_name}{format_signature(method)}`",
                "",
                format_docstring(method.__doc__),
                "",
            ])

    return "\n".join(lines)


def generate_function_doc(name: str, func: Any) -> str:
    """Generate documentation for a function.

    Args:
        name: Function name.
        func: Function object.

    Returns:
        Markdown documentation.
    """
    lines = [
        f"### `{name}{format_signature(func)}`",
        "",
        format_docstring(func.__doc__),
        "",
    ]

    return "\n".join(lines)


def generate_module_doc(module_name: str) -> str:
    """Generate documentation for a module.

    Args:
        module_name: Fully qualified module name.

    Returns:
        Markdown documentation.
    """
    try:
        module = importlib.import_module(module_name)
    except ImportError as e:
        return f"# {module_name}\n\n*Failed to import: {e}*\n"

    members = get_module_members(module)

    lines = [
        f"# {module_name}",
        "",
        format_docstring(module.__doc__),
        "",
    ]

    # Classes
    if members["classes"]:
        lines.extend([
            "## Classes",
            "",
        ])
        for name, cls in members["classes"]:
            lines.append(generate_class_doc(name, cls))

    # Functions
    if members["functions"]:
        lines.extend([
            "## Functions",
            "",
        ])
        for name, func in members["functions"]:
            lines.append(generate_function_doc(name, func))

    # Constants
    if members["constants"]:
        lines.extend([
            "## Constants",
            "",
            "| Name | Value |",
            "|------|-------|",
        ])
        for name, value in members["constants"]:
            lines.append(f"| `{name}` | `{repr(value)[:50]}` |")
        lines.append("")

    return "\n".join(lines)


def generate_all_docs(output_dir: Path) -> list[str]:
    """Generate documentation for all UCID modules.

    Args:
        output_dir: Output directory.

    Returns:
        List of generated files.
    """
    generated = []

    # Core modules
    modules = [
        "ucid",
        "ucid.core.parser",
        "ucid.core.validator",
        "ucid.core.models",
        "ucid.core.errors",
    ]

    for module_name in modules:
        doc = generate_module_doc(module_name)

        # Determine output path
        parts = module_name.split(".")
        if len(parts) == 1:
            file_path = output_dir / "index.md"
        else:
            subdir = output_dir / "/".join(parts[1:-1])
            subdir.mkdir(parents=True, exist_ok=True)
            file_path = subdir / f"{parts[-1]}.md"

        file_path.write_text(doc, encoding="utf-8")
        generated.append(str(file_path))

    return generated


def main(argv: Sequence[str] | None = None) -> int:
    """Main entry point for documentation generator.

    Args:
        argv: Command-line arguments.

    Returns:
        Exit code.
    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("docs/api"),
        help="Output directory (default: docs/api)",
    )
    parser.add_argument(
        "--module",
        help="Specific module to document",
    )

    args = parser.parse_args(argv)

    print("=" * 60)
    print("UCID Documentation Generator")
    print("=" * 60)

    # Ensure output directory exists
    args.output.mkdir(parents=True, exist_ok=True)

    if args.module:
        # Generate single module
        doc = generate_module_doc(args.module)
        output_file = args.output / f"{args.module.split('.')[-1]}.md"
        output_file.write_text(doc, encoding="utf-8")
        print(f"Generated: {output_file}")
    else:
        # Generate all documentation
        generated = generate_all_docs(args.output)
        print(f"\nGenerated {len(generated)} documentation files:")
        for file_path in generated:
            print(f"  - {file_path}")

    print("\n" + "=" * 60)
    print("Documentation generation complete!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
