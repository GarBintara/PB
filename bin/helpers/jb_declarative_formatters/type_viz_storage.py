import re
from collections import defaultdict

import six


# storage of grouped type vizualizers from single source
class TypeVizStorage(object):
    class Item(object):
        def __init__(self):
            self.exact_match = []
            self.wildcard_match = []

        def __str__(self):
            return 'total: {}, wildcard: {}'.format(str(self.exact_match), str(self.wildcard_match))

    def __init__(self, logger=None):
        self._types = defaultdict(self.Item)  # maps top-level template typenames to array of TypeViz
        self._logger = logger

    def add_type(self, type_viz):
        for type_viz_name in type_viz.type_viz_names:
            key = _build_key(type_viz_name.type_name_template)
            if type_viz_name.has_wildcard:
                regex = "^" + _build_regex(type_viz_name.type_name_template) + "$"
                item = self._types[key]
                # TODO: use bisect.insort
                item.wildcard_match.append((type_viz, type_viz_name, regex))
                item.wildcard_match.sort(key=lambda x: -x[0].priority)
            else:
                type_name = str(type_viz_name.type_name_template)
                item = self._types[key]
                # TODO: use bisect.insort
                item.exact_match.append((type_viz, type_viz_name, type_name))
                item.exact_match.sort(key=lambda x: -x[0].priority)

    def iterate_exactly_matched_type_viz(self):
        for item in six.itervalues(self._types):
            for viz, type_viz_name, type_name in item.exact_match:
                yield type_name, viz, type_viz_name

    def iterate_wildcard_matched_type_viz(self):
        for item in six.itervalues(self._types):
            for viz, type_viz_name, regex in item.wildcard_match:
                yield regex, viz, type_viz_name

    def get_matched_types(self, type_name_template):
        key = _build_key(type_name_template)
        item = self._types.get(key)

        if item:
            req_type_name = str(type_name_template)
            for match in item.exact_match:
                type_viz, type_viz_name, type_name = match
                if req_type_name == type_name:
                    yield type_viz, type_viz_name

            for wildcard_viz, type_viz_name, _ in item.wildcard_match:
                wildcard = type_viz_name.type_name_template
                if wildcard.match(type_name_template, None, self._logger):
                    yield wildcard_viz, type_viz_name


def _build_key(type_name_template):
    idx_prefix_end = type_name_template.name.find('<')
    if idx_prefix_end == -1:
        return type_name_template.name
    return type_name_template.name[:idx_prefix_end]


def _build_regex(type_name_template):
    if type_name_template.is_wildcard:
        return '(.*)'
    if not type_name_template.args:
        return re.escape(type_name_template.name)
    return type_name_template.fmt.format(*[_build_regex(arg) for arg in type_name_template.args])
