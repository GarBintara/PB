def make_absolute_name(root, name):
    return '.'.join([root, name])


def register_lldb_commands(debugger, cmd_map):
    for func, cmd in cmd_map.items():
        debugger.HandleCommand('command script add -f {func} {cmd}'.format(func=func, cmd=cmd))
