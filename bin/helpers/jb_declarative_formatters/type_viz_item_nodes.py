from .type_viz_mixins import \
    TypeVizItemFormattedExpressionNodeMixin, \
    TypeVizItemValueNodeMixin, \
    TypeVizItemNamedNodeMixin, \
    TypeVizItemConditionalNodeMixin, \
    TypeVizItemOptionalNodeMixin


class TypeVizItemSizeTypeNode(TypeVizItemConditionalNodeMixin,
                              TypeVizItemOptionalNodeMixin,
                              TypeVizItemValueNodeMixin):
    def __init__(self, text, condition=None, optional=False):
        super(TypeVizItemSizeTypeNode, self).__init__(text=text, condition=condition, optional=optional)


class TypeVizItemValuePointerTypeNode(TypeVizItemConditionalNodeMixin,
                                      TypeVizItemFormattedExpressionNodeMixin):
    def __init__(self, expr, condition=None):
        super(TypeVizItemValuePointerTypeNode, self).__init__(expr=expr, condition=condition)


class TypeVizItemIndexNodeTypeNode(TypeVizItemConditionalNodeMixin,
                                   TypeVizItemFormattedExpressionNodeMixin):
    def __init__(self, expr, condition=None):
        super(TypeVizItemIndexNodeTypeNode, self).__init__(expr=expr, condition=condition)


class TypeVizItemListItemsHeadPointerTypeNode(TypeVizItemValueNodeMixin):
    def __init__(self, text):
        super(TypeVizItemListItemsHeadPointerTypeNode, self).__init__(text=text)


class TypeVizItemListItemsNextPointerTypeNode(TypeVizItemValueNodeMixin):
    def __init__(self, text):
        super(TypeVizItemListItemsNextPointerTypeNode, self).__init__(text=text)


class TypeVizItemListItemsIndexNodeTypeNode(TypeVizItemNamedNodeMixin,
                                            TypeVizItemFormattedExpressionNodeMixin):
    def __init__(self, expr, name=None):
        super(TypeVizItemListItemsIndexNodeTypeNode, self).__init__(expr=expr, name=name)


class TypeVizItemTreeHeadPointerTypeNode(TypeVizItemValueNodeMixin):
    def __init__(self, text):
        super(TypeVizItemTreeHeadPointerTypeNode, self).__init__(text=text)


class TypeVizItemTreeChildPointerTypeNode(TypeVizItemValueNodeMixin):
    def __init__(self, text):
        super(TypeVizItemTreeChildPointerTypeNode, self).__init__(text=text)


class TypeVizItemTreeNodeTypeNode(TypeVizItemNamedNodeMixin,
                                  TypeVizItemConditionalNodeMixin,
                                  TypeVizItemFormattedExpressionNodeMixin):
    def __init__(self, expr, name=None, condition=None):
        super(TypeVizItemTreeNodeTypeNode, self).__init__(expr=expr, name=name, condition=condition)
