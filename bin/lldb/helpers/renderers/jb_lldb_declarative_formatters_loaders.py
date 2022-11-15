from .jb_lldb_logging import log

g_type_viz_loaders = {}


class TypeVizLoaderException(Exception):
    pass


def type_viz_loader_add(tag, loader):
    log("Registering loader for type viz of type '{}'", tag)
    if tag in g_type_viz_loaders:
        log("Loader for type viz of type '{}' already exists", tag)  # Warning
    g_type_viz_loaders[tag] = loader


def type_viz_loader_remove(tag):
    log("Removing loader for type viz of type '{}'", tag)
    del g_type_viz_loaders[tag]


def type_viz_loader_get_list():
    return g_type_viz_loaders


def type_viz_loader_get(tag):
    return g_type_viz_loaders[tag]
