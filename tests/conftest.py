"""pytest configuration for the test suite.

The project is a single top-level module (``restore_videos.py``) written
against the standard library only, with no packaging: there is nothing to
install. The tests therefore put the repository root on ``sys.path`` so that
``import restore_videos`` works whatever directory pytest is started from.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
