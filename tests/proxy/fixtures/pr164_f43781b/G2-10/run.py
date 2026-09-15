#!/usr/bin/env python3
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from fixture import scenario_main
scenario_main(Path(__file__).resolve().parent)
