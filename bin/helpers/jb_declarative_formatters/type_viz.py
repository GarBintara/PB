class TypeVizName(object):
    def __init__(self, type_name, type_name_template):
        self.type_name = type_name
        self.type_name_template = type_name_template

    @property
    def has_wildcard(self):
        return self.type_name_template.has_wildcard

    def __str__(self):
        return self.type_name


class TypeViz(object):
    def __init__(self, type_viz_names, is_inheritable, priority, logger=None):
        self.logger = logger  # TODO: or stub

        self.type_viz_names = type_viz_names  # list[TypeVizName]
        self.is_inheritable = is_inheritable
        self.priority = priority
        self.summaries = []
        self.item_providers = None
