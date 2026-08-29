#!/usr/bin/env python3
"""Run from a git clone: python3 llm_host_guard.py  (same as: python3 -m llm_host_guard)"""
import sys
from llm_host_guard.cli import main

sys.exit(main())
