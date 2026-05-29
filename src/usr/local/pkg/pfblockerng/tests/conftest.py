import sys
import os
import builtins

# pfb_unbound.py is designed to run inside Unbound's Python plugin loader,
# which injects Unbound-specific functions (log_info, log_err, …) as
# module-level globals before executing the script.  Provide a no-op stub
# for the one such function that is called at module level so the file can
# be imported in a plain Python environment for unit testing.
builtins.log_info = lambda msg: None

# Make pfb_unbound importable from the parent directory without installation.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
