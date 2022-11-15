from jb_declarative_formatters.parsers.natvis import natvis_parse_file
from jb_declarative_formatters.type_viz_storage import TypeVizStorage
from .jb_lldb_logging import log, get_logger


def natvis_loader(filepath):
    storage = TypeVizStorage(get_logger())
    load_natvis_file(storage, filepath)
    return storage


def load_natvis_file(storage, filepath):
    log("Parsing {}", filepath)
    for type_viz in natvis_parse_file(filepath, get_logger()):
        log("Register types: {}", ', '.join(map(_type_viz_name_pp, type_viz.type_viz_names)))
        storage.add_type(type_viz)


def _type_viz_name_pp(type_viz_name):
    return "'" + str(type_viz_name) + "'"
