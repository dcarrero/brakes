# Seeded by brakes (stack-packs, python-uv): held-out properties run
# with fresh randomness. Hypothesis's built-in `ci` profile is active whenever
# `CI` is set and has `derandomize=True` and `database=None`; this profile keeps
# `ci` as its parent (so `print_blob=True` and no database survive) and turns
# randomness back on; the job passes the recorded seed with `--hypothesis-seed`.
import os

from hypothesis import settings

settings.register_profile(
    "heldout",
    parent=settings.get_profile("ci"),
    derandomize=False,
    max_examples=int(os.environ.get("HELDOUT_EXAMPLES", "200")),
)
settings.load_profile("heldout")
