import shlex

from renderers.jb_lldb_utils import make_absolute_name, register_lldb_commands
from renderers.jb_lldb_declarative_formatters_options import set_diagnostics_level, DiagnosticsLevel
from renderers.jb_lldb_logging import set_logging_level


def __lldb_init_module(debugger, internal_dict):
    # print("JetBrains LLDB module for logging initialized")
    commands_list = {
        make_absolute_name(__name__, '_cmd_set_diagnostics_level'): 'jb_renderers_set_diagnostics_level',
    }
    register_lldb_commands(debugger, commands_list)

    # set errors-only diagnostics level by default
    set_diagnostics_level(DiagnosticsLevel.ERRORS_ONLY)


def _cmd_set_diagnostics_level(debugger, command, exe_ctx, result, internal_dict):
    cmd = shlex.split(command)
    if len(cmd) != 1:
        result.SetError('Single argument expected.\nUsage: jb_renderers_set_diagnostics_level <level>')
        return

    try:
        level = DiagnosticsLevel(int(cmd[0]))
    except ValueError as e:
        result.SetError('Invalid argument passed, required level as integer in range [0, 2]: {}'.format(str(e)))
        return

    try:
        set_diagnostics_level(level)
        if level == DiagnosticsLevel.VERBOSE:
            set_logging_level(1)
        else:
            set_logging_level(0)
    except Exception as e:
        result.SetError(str(e))
