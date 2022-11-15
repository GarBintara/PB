from enum import Enum

g_force_suppress_errors = False
g_max_num_children = 10000
g_max_recursion_level = 50


class DiagnosticsLevel(Enum):
    DISABLED = 0
    ERRORS_ONLY = 1
    VERBOSE = 2


def set_diagnostics_level(level):
    global g_force_suppress_errors
    if level == DiagnosticsLevel.VERBOSE:
        g_force_suppress_errors = False
    elif level == DiagnosticsLevel.ERRORS_ONLY:
        g_force_suppress_errors = False
    elif level == DiagnosticsLevel.DISABLED:
        g_force_suppress_errors = True
    else:
        raise Exception('Invalid argument passed, expected level 0, 1 or 2')


# TODO: set_max_num_children
