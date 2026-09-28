"""Command-line entry points for the Merkle Tree Lab.

Run with ``python3 -m lab.cli <command> ...``. See IMPL.md for a walkthrough.

``build_parser`` and ``main`` live in :mod:`lab.cli.__main__`, which is left
unimported here on purpose: importing a module named ``__main__`` from a package
initialiser makes ``python -m lab.cli`` import it twice and warn about it.
"""
