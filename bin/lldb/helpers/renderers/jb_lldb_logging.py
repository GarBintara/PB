import lldb
import lldb.formatters

logger = lldb.formatters.Logger.Logger()
lldb.formatters.Logger._lldb_formatters_debug_level = 0


def set_logging_level(level):
    lldb.formatters.Logger._lldb_formatters_debug_level = level
    # reinit logger
    global logger
    logger = lldb.formatters.Logger.Logger()


def log(fmt, *args, **kwargs):
    logger >> fmt.format(*args, **kwargs)


def get_logger():
    return logger
