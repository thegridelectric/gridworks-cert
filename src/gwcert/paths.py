"""Default path definitions used by gwcert."""

from pathlib import Path

import xdg


DEFAULT_CA_DIR = Path(xdg.xdg_data_home()) / "gridworks" / "ca"
DEFAULT_CERTS_DIR = DEFAULT_CA_DIR / "certs"
