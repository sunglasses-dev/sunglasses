# SUNGLASSES — Real-time filter for AI agent inputs
# https://sunglasses.dev | https://github.com/sunglasses-dev/sunglasses
# MIT License
#
# "Don't let your agents get fooled."

def _drop_implicit_first_path_entry():
    """Under `python -m sunglasses.<module>`, drop the implicit first path entry (the current folder).

    This runs before any other import of the package, so the modules that follow (json, re, ...)
    come from Python and not from the folder the command was started in. It is what `-P` does,
    for command lines written BEFORE `-P` was used (an older hook in someone's settings file).
    Limits, stated: `python -m` has already imported what `runpy` needs, and a `sunglasses`
    folder in the current folder was found before this file ran. It does nothing unless
    `python -m sunglasses...` is the command being run, so a program that merely imports
    sunglasses keeps its own path. See _launch.py.
    """
    import sys
    if sys.argv[:1] != ["-m"]:          # `-m` is the placeholder until runpy has located the module
        return
    frame = sys._getframe(1)
    while frame is not None:
        code = frame.f_code
        if code.co_name == "_run_module_as_main" and "runpy" in code.co_filename:   # "<frozen runpy>" from 3.11
            name = frame.f_locals.get("mod_name") or ""
            if name == "sunglasses" or name.startswith("sunglasses."):
                import os
                if sys.path and sys.path[0] in ("", os.getcwd()):
                    del sys.path[0]
            return
        frame = frame.f_back


try:
    _drop_implicit_first_path_entry()
except Exception:                       # a guard must never be the reason the package does not import
    pass
del _drop_implicit_first_path_entry

__version__ = "0.6.22"
