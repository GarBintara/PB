from .type_viz_expression import TypeVizInterpolatedString
from .type_viz_mixins import TypeVizItemConditionalNodeMixin, TypeVizItemOptionalNodeMixin


class TypeVizSummary(TypeVizItemConditionalNodeMixin,
                     TypeVizItemOptionalNodeMixin):
    def __init__(self, value, condition=None, optional=False):
        super(TypeVizSummary, self).__init__(condition=condition, optional=optional)
        assert isinstance(value, TypeVizInterpolatedString)
        self.value = value
