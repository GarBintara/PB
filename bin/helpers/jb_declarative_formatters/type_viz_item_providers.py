from enum import Enum, auto

from .type_viz_mixins import \
    TypeVizItemFormattedExpressionNodeMixin, \
    TypeVizItemNamedNodeMixin, \
    TypeVizItemConditionalNodeMixin, \
    TypeVizItemOptionalNodeMixin


class TypeVizItemProviderTypeKind(Enum):
    Single = auto(),
    Expanded = auto(),
    # Synthetic = auto(),
    ArrayItems = auto(),
    IndexListItems = auto(),
    LinkedListItems = auto(),
    TreeItems = auto(),


class TypeVizItemProviderSingle(TypeVizItemFormattedExpressionNodeMixin,
                                TypeVizItemNamedNodeMixin,
                                TypeVizItemConditionalNodeMixin,
                                TypeVizItemOptionalNodeMixin):
    kind = TypeVizItemProviderTypeKind.Single

    def __init__(self, name, expr, condition=None, optional=False):
        super(TypeVizItemProviderSingle, self).__init__(expr=expr, name=name, condition=condition, optional=optional)


class TypeVizItemProviderExpanded(TypeVizItemFormattedExpressionNodeMixin,
                                  TypeVizItemConditionalNodeMixin,
                                  TypeVizItemOptionalNodeMixin):
    kind = TypeVizItemProviderTypeKind.Expanded

    def __init__(self, expr, condition=None, optional=False):
        super(TypeVizItemProviderExpanded, self).__init__(expr=expr, condition=condition, optional=optional)


class TypeVizItemProviderArrayItems(TypeVizItemConditionalNodeMixin,
                                    TypeVizItemOptionalNodeMixin):
    kind = TypeVizItemProviderTypeKind.ArrayItems

    def __init__(self, size_nodes, value_pointer_nodes, condition=None, optional=False):
        super(TypeVizItemProviderArrayItems, self).__init__(condition=condition, optional=optional)
        self.size_nodes = size_nodes  # list[TypeVizItemSizeTypeNode]
        self.value_pointer_nodes = value_pointer_nodes  # list[TypeVizItemValuePointerTypeNode]


class TypeVizItemProviderIndexListItems(TypeVizItemConditionalNodeMixin,
                                        TypeVizItemOptionalNodeMixin):
    kind = TypeVizItemProviderTypeKind.IndexListItems

    def __init__(self, size_nodes, value_node_nodes, condition=None, optional=False):
        super(TypeVizItemProviderIndexListItems, self).__init__(condition=condition, optional=optional)
        self.size_nodes = size_nodes  # list[TypeVizItemSizeTypeNode]
        self.value_node_nodes = value_node_nodes  # list[TypeVizItemIndexNodeTypeNode]


class TypeVizItemProviderLinkedListItems(TypeVizItemConditionalNodeMixin,
                                         TypeVizItemOptionalNodeMixin):
    kind = TypeVizItemProviderTypeKind.LinkedListItems

    def __init__(self, size_nodes, head_pointer_node, next_pointer_node, value_node_node, condition=None,
                 optional=False):
        super(TypeVizItemProviderLinkedListItems, self).__init__(condition=condition, optional=optional)
        self.size_nodes = size_nodes  # list[TypeVizItemSizeTypeNode]
        self.head_pointer_node = head_pointer_node  # TypeVizItemListItemsHeadPointerTypeNode
        self.next_pointer_node = next_pointer_node  # TypeVizItemListItemsNextPointerTypeNode
        self.value_node_node = value_node_node  # TypeVizItemListItemsIndexNodeTypeNode


class TypeVizItemProviderTreeItems(TypeVizItemConditionalNodeMixin,
                                   TypeVizItemOptionalNodeMixin):
    kind = TypeVizItemProviderTypeKind.TreeItems

    def __init__(self, size_nodes, head_pointer_node, left_pointer_node, right_pointer_node, value_node_node,
                 condition=None,
                 optional=False):
        super(TypeVizItemProviderTreeItems, self).__init__(condition=condition, optional=optional)
        self.size_nodes = size_nodes  # list[TypeVizItemSizeTypeNode]
        self.head_pointer_node = head_pointer_node  # TypeVizItemTreeHeadPointerTypeNode
        self.left_pointer_node = left_pointer_node  # TypeVizItemTreeChildPointerTypeNode
        self.right_pointer_node = right_pointer_node  # TypeVizItemTreeChildPointerTypeNode
        self.value_node_node = value_node_node  # TypeVizItemTreeNodeTypeNode
