import re
import traceback
from xml.etree import ElementTree
from xml.sax import saxutils

from jb_declarative_formatters import *
from jb_declarative_formatters.parsers.type_name_parser import parse_type_name_template, TypeNameParsingError
from six import StringIO

NATVIS_SCHEMA_NAMESPACE = 'http://schemas.microsoft.com/vstudio/debugger/natvis/2010'


class NatvisParsingError(Exception):
    pass


_NS = {'natvis': NATVIS_SCHEMA_NAMESPACE}


def natvis_parse_file(path, logger=None):
    tree = ElementTree.parse(path)
    root = tree.getroot()
    for node_type_name in root.findall('natvis:Type', _NS):
        try:
            yield natvis_parse_type(node_type_name, logger)
        except NatvisParsingError as e:
            # expected parsing error happened
            # - skip node and continue
            if logger:
                logger >> str(e)
            continue
        except Exception:
            # unexpected parsing error happened
            if logger:
                logger >> traceback.format_exc()
            else:
                print(traceback.format_exc())
            continue


def _unescape(value):
    if value is None:
        return value
    return saxutils.unescape(value)


def _make_tag(tag):
    return '{{{}}}{}'.format(NATVIS_SCHEMA_NAMESPACE, tag)


def _parse_type_name_alternatives(node_type_name):
    try:
        name = node_type_name.attrib['Name']
    except KeyError:
        raise NatvisParsingError("Missing required attribute 'Name'")

    name = _unescape(name)

    # support non-documented way to declare alternative type names used from UE4.17
    for alt_name in name.split('|'):
        yield alt_name

    # support non-documented AlternativeType nodes found in stl.natvis
    for alt_name_node in node_type_name.findall('natvis:AlternativeType', _NS):
        yield _unescape(alt_name_node.attrib['Name'])


def _parse_type_priority(node_type_name, logger):
    priorities = {
        'Low': 1,
        'MediumLow': 2,
        'Medium': 3,
        'MediumHigh': 4,
        'High': 5,
    }
    priority_str = node_type_name.attrib.get('Priority', 'Medium')
    try:
        return priorities[priority_str]
    except KeyError:
        raise NatvisParsingError('Unknown priority {}'.format(priority_str))


def natvis_parse_type(node_type_name, logger=None):
    _item_node_parsers = {
        _make_tag('Item'): _natvis_node_parse_item,
        _make_tag('ExpandedItem'): _natvis_node_parse_expanded_item,
        _make_tag('ArrayItems'): _natvis_node_parse_array_items,
        _make_tag('IndexListItems'): _natvis_node_parse_index_list_items,
        _make_tag('LinkedListItems'): _natvis_node_parse_linked_list_items,
        _make_tag('TreeItems'): _natvis_node_parse_tree_items,
    }

    type_viz_names = []
    alt_names = _parse_type_name_alternatives(node_type_name)
    for alt_name in alt_names:
        try:
            if logger:
                logger >> "Parsing type name '{}'".format(alt_name)

            name_ast = parse_type_name_template(alt_name)
        except TypeNameParsingError as e:
            raise NatvisParsingError(e)
        type_viz_names.append(TypeVizName(alt_name, name_ast))

    inheritable = node_type_name.attrib.get('Inheritable', 'true') == 'true'
    priority = _parse_type_priority(node_type_name, logger)
    type_viz = TypeViz(type_viz_names, inheritable, priority)

    intrinsics = []
    for intrinsic in node_type_name.findall('natvis:Intrinsic', _NS):
        name, expr = _natvis_node_parse_intrinsic(intrinsic, intrinsics)
        intrinsics.append((name, expr))
    intrinsics.sort(key=lambda x: len(x[0]), reverse=True)

    for display_string_node in node_type_name.findall('natvis:DisplayString', _NS):
        value = _natvis_node_parse_expression(display_string_node.text or '', intrinsics)
        condition = _natvis_node_parse_condition(display_string_node, intrinsics)
        optional = _natvis_node_parse_optional(display_string_node)
        display_string_expression = _natvis_node_parse_interpolated_string(value, intrinsics)
        type_viz.summaries.append(TypeVizSummary(display_string_expression, condition, optional))

    expand_node = node_type_name.find('natvis:Expand', _NS)
    if expand_node:
        type_viz.item_providers = []

        for node in expand_node:
            parse_fn = _item_node_parsers.get(node.tag)
            if parse_fn:
                item_provider = parse_fn(node, intrinsics)
                if item_provider:
                    type_viz.item_providers.append(item_provider)
    return type_viz


NATVIS_FORMAT_SPECIFIERS_MAPPING = {
    'd': TypeVizFormatSpec.DECIMAL,
    'o': TypeVizFormatSpec.OCTAL,
    'x': TypeVizFormatSpec.HEX,
    'h': TypeVizFormatSpec.HEX,
    'X': TypeVizFormatSpec.HEX_UPPERCASE,
    'H': TypeVizFormatSpec.HEX_UPPERCASE,
    'xb': TypeVizFormatSpec.HEX_NO_PREFIX,
    'hb': TypeVizFormatSpec.HEX_NO_PREFIX,
    'Xb': TypeVizFormatSpec.HEX_UPPERCASE_NO_PREFIX,
    'Hb': TypeVizFormatSpec.HEX_UPPERCASE_NO_PREFIX,
    'b': TypeVizFormatSpec.BINARY,
    'bb': TypeVizFormatSpec.BINARY_NO_PREFIX,
    'e': TypeVizFormatSpec.SCIENTIFIC,
    'g': TypeVizFormatSpec.SCIENTIFIC_MIN,
    'c': TypeVizFormatSpec.CHARACTER,
    's': TypeVizFormatSpec.STRING,
    'sb': TypeVizFormatSpec.STRING_NO_QUOTES,
    's8': TypeVizFormatSpec.UTF8_STRING,
    's8b': TypeVizFormatSpec.UTF8_STRING_NO_QUOTES,
    'su': TypeVizFormatSpec.WIDE_STRING,
    'sub': TypeVizFormatSpec.WIDE_STRING_NO_QUOTES,
    'bstr': TypeVizFormatSpec.WIDE_STRING,
    's32': TypeVizFormatSpec.UTF32_STRING,
    's32b': TypeVizFormatSpec.UTF32_STRING_NO_QUOTES,
    'en': TypeVizFormatSpec.ENUM,
    'hv': TypeVizFormatSpec.HEAP_ARRAY,
    'na': TypeVizFormatSpec.NO_ADDRESS,
    'nd': TypeVizFormatSpec.NO_DERIVED,
    'nr': TypeVizFormatSpec.NO_RAW_VIEW,
    'nvo': TypeVizFormatSpec.NUMERIC_RAW_VIEW,
    '!': TypeVizFormatSpec.RAW_FORMAT,
    'hr': TypeVizFormatSpec.IGNORED,
    'wc': TypeVizFormatSpec.IGNORED,
    'wm': TypeVizFormatSpec.IGNORED,
}

_NATVIS_SPECS_REGEX = re.compile(r"^(?:\[(.*)\])?(.*)$")
_NATVIS_VIEW_SPECS_REGEX = re.compile(r"^view\s*\((.*)\)\s*$")


def _natvis_parse_expression_specs(specs):
    match = _NATVIS_SPECS_REGEX.match(specs)
    if not match:
        return None, None, None

    array_len = match.group(1)
    if array_len:
        array_len = array_len.strip()
    spec = match.group(2)
    if spec:
        spec = spec.strip()
    spec_value = NATVIS_FORMAT_SPECIFIERS_MAPPING.get(spec, None)
    view_spec = None
    if not spec_value:
        view_match = _NATVIS_VIEW_SPECS_REGEX.match(spec)
        if view_match:
            view_spec = view_match.group(1)
            if view_spec:
                view_spec = view_spec.strip()

    return array_len, spec_value, view_spec


def _apply_intrinsics_to_expression(expression, intrinsics):
    for (intr_key, intr_value) in intrinsics:
        expression = expression.replace(intr_key + '()', '(' + intr_value + ')')
    return expression


def _natvis_node_parse_expression(expression_text, intrinsics):
    if expression_text is None:
        return None
    expression_text = _unescape(expression_text)
    expression_text = expression_text.replace('\n', '')

    return _apply_intrinsics_to_expression(expression_text, intrinsics)


def _natvis_node_parse_formatted_expression(expression_text, intrinsics):
    if expression_text is None:
        return None
    expression_text = _unescape(expression_text)
    expression_text = expression_text.replace('\n', '')

    parts = expression_text.rsplit(',', 1)
    array_size = None
    format_spec = None
    view_spec = None
    if len(parts) == 2:
        specs = parts[1].strip()
        array_size, format_spec, view_spec = _natvis_parse_expression_specs(specs)

    if array_size or format_spec or view_spec:
        expression = parts[0].strip()
    else:
        expression = expression_text.strip()

    expression = _apply_intrinsics_to_expression(expression, intrinsics)
    return TypeVizExpression(expression, array_size, format_spec, view_spec)


def _natvis_node_parse_interpolated_string(text, intrinsics):
    text_len = len(text)
    i = 0
    s = StringIO()
    expr_list = []
    while i < text_len:
        if text[i] == '{':
            i += 1
            if i < text_len and text[i] == '{':
                # '{{' is escaped '{'
                s.write('{{')
                i += 1
                continue

            idx_start = i
            # get expression slice to evaluate
            while i < text_len:
                if text[i] == '}':
                    break
                i += 1
            else:
                raise NatvisParsingError("missing '}'")

            s.write("{}")  # append parameter slot to format string for expression
            expr = _natvis_node_parse_formatted_expression(text[idx_start:i], intrinsics)
            expr_list.append(expr)
            i += 1
            continue

        if text[i] == '}':
            s.write('}}')
            i += 1
            if i < text_len and text[i] == '}':
                # '}}' is escaped '}'
                i += 1
            continue

        # TODO: write whole slices, not by single character
        # some symbol
        s.write(text[i])
        i += 1

    fmt = s.getvalue()
    return TypeVizInterpolatedString(fmt, expr_list)


def _natvis_node_parse_name(item_node):
    return _unescape(item_node.attrib.get('Name', None))


def _natvis_node_parse_item(item_node, intrinsics):
    item_name = _natvis_node_parse_name(item_node)
    if item_name is None:
        raise NatvisParsingError('Name is required')
    item_condition = _natvis_node_parse_condition(item_node, intrinsics)
    item_optional = _natvis_node_parse_optional(item_node)
    item_expression = _natvis_node_parse_formatted_expression(item_node.text or '', intrinsics)
    return TypeVizItemProviderSingle(item_name, item_expression, item_condition, item_optional)


def _natvis_node_parse_expanded_item(item_node, intrinsics):
    item_condition = _natvis_node_parse_condition(item_node, intrinsics)
    item_optional = _natvis_node_parse_optional(item_node)
    item_expression = _natvis_node_parse_formatted_expression(item_node.text or '', intrinsics)
    return TypeVizItemProviderExpanded(item_expression, item_condition, item_optional)


def _natvis_node_parse_size_node(item_node, intrinsics):
    nodes = item_node.findall('natvis:Size', _NS)
    if nodes is None:
        return None

    values = []
    for node in nodes:
        condition = _natvis_node_parse_condition(node, intrinsics)
        optional = _natvis_node_parse_optional(node)
        value = _natvis_node_parse_expression(node.text or '', intrinsics)

        values.append(TypeVizItemSizeTypeNode(value, condition, optional))

    return values


def _natvis_node_parse_value_pointer_node(item_node, intrinsics):
    nodes = item_node.findall('natvis:ValuePointer', _NS)
    if nodes is None:
        return None

    values = []
    for node in nodes:
        condition = _natvis_node_parse_condition(node, intrinsics)
        value = _natvis_node_parse_formatted_expression(node.text or '', intrinsics)

        values.append(TypeVizItemValuePointerTypeNode(value, condition))

    return values


def _natvis_node_parse_array_items(item_node, intrinsics):
    item_condition = _natvis_node_parse_condition(item_node, intrinsics)
    item_optional = _natvis_node_parse_optional(item_node)

    items_size = _natvis_node_parse_size_node(item_node, intrinsics)
    if items_size is None:
        return None

    items_value_pointer = _natvis_node_parse_value_pointer_node(item_node, intrinsics)
    if items_value_pointer is None:
        return None

    return TypeVizItemProviderArrayItems(items_size, items_value_pointer, item_condition, item_optional)


def _natvis_node_parse_index_node(item_node, intrinsics):
    nodes = item_node.findall('natvis:ValueNode', _NS)
    if nodes is None:
        return None

    values = []
    for node in nodes:
        condition = _natvis_node_parse_condition(node, intrinsics)
        value = _natvis_node_parse_formatted_expression(node.text or '', intrinsics)

        values.append(TypeVizItemIndexNodeTypeNode(value, condition))

    return values


def _natvis_node_parse_index_list_items(item_node, intrinsics):
    item_condition = _natvis_node_parse_condition(item_node, intrinsics)
    item_optional = _natvis_node_parse_optional(item_node)

    items_size = _natvis_node_parse_size_node(item_node, intrinsics)
    if items_size is None:
        return None

    items_value_node = _natvis_node_parse_index_node(item_node, intrinsics)
    if items_value_node is None:
        return None

    return TypeVizItemProviderIndexListItems(items_size, items_value_node, item_condition, item_optional)


def _natvis_node_parse_linked_list_head_pointer(item_node, intrinsics):
    nodes = item_node.findall('natvis:HeadPointer', _NS)
    if nodes is None:
        return None

    if len(nodes) != 1:
        raise NatvisParsingError('Only one HeadPointer node allowed')
    node = nodes[0]

    node_expression = _natvis_node_parse_expression(node.text or '', intrinsics)

    return TypeVizItemListItemsHeadPointerTypeNode(node_expression)


def _natvis_node_parse_linked_list_next_pointer(item_node, intrinsics):
    nodes = item_node.findall('natvis:NextPointer', _NS)
    if nodes is None:
        return None

    if len(nodes) != 1:
        raise NatvisParsingError('Only one NextPointer node allowed')
    node = nodes[0]

    node_expression = _natvis_node_parse_expression(node.text or '', intrinsics)

    return TypeVizItemListItemsNextPointerTypeNode(node_expression)


def _natvis_node_parse_linked_list_value_node(item_node, intrinsics):
    nodes = item_node.findall('natvis:ValueNode', _NS)
    if nodes is None:
        return None

    if len(nodes) != 1:
        raise NatvisParsingError('Only one ValueNode node allowed')
    node = nodes[0]

    node_name_str = _natvis_node_parse_name(node)
    node_name = _natvis_node_parse_interpolated_string(node_name_str, intrinsics) if node_name_str is not None else None
    node_expression = _natvis_node_parse_formatted_expression(node.text or '', intrinsics)

    return TypeVizItemListItemsIndexNodeTypeNode(node_expression, node_name)


def _natvis_node_parse_linked_list_items(item_node, intrinsics):
    item_condition = _natvis_node_parse_condition(item_node, intrinsics)
    item_optional = _natvis_node_parse_optional(item_node)

    items_size = _natvis_node_parse_size_node(item_node, intrinsics)
    # size can be omitted

    item_head_pointer = _natvis_node_parse_linked_list_head_pointer(item_node, intrinsics)
    if item_head_pointer is None:
        return None

    item_next_pointer = _natvis_node_parse_linked_list_next_pointer(item_node, intrinsics)
    if item_next_pointer is None:
        return None

    items_value_node = _natvis_node_parse_linked_list_value_node(item_node, intrinsics)
    if items_value_node is None:
        return None

    return TypeVizItemProviderLinkedListItems(items_size, item_head_pointer, item_next_pointer, items_value_node,
                                              item_condition, item_optional)


def _natvis_node_parse_tree_pointer_helper(item_node, node_name, intrinsics):
    nodes = item_node.findall('natvis:{}'.format(node_name), _NS)
    if nodes is None:
        return None

    if len(nodes) != 1:
        raise NatvisParsingError('Only one {} node allowed'.format(node_name))
    node = nodes[0]

    node_expression = _natvis_node_parse_expression(node.text or '', intrinsics)
    return node_expression


def _natvis_node_parse_tree_head_pointer(item_node, intrinsics):
    node_expression = _natvis_node_parse_tree_pointer_helper(item_node, 'HeadPointer', intrinsics)
    if node_expression is None:
        return None
    return TypeVizItemTreeHeadPointerTypeNode(node_expression)


def _natvis_node_parse_tree_child_pointer(item_node, node_name, intrinsics):
    node_expression = _natvis_node_parse_tree_pointer_helper(item_node, node_name, intrinsics)
    if node_expression is None:
        return None
    return TypeVizItemTreeChildPointerTypeNode(node_expression)


def _natvis_node_parse_tree_value_node(item_node, intrinsics):
    nodes = item_node.findall('natvis:ValueNode', _NS)
    if nodes is None:
        return None

    if len(nodes) != 1:
        raise NatvisParsingError('Only one ValueNode node allowed')
    node = nodes[0]

    node_name_str = _natvis_node_parse_name(node)
    node_name = _natvis_node_parse_interpolated_string(node_name_str, intrinsics) if node_name_str is not None else None
    node_expression = _natvis_node_parse_formatted_expression(node.text or '', intrinsics)
    node_condition = _natvis_node_parse_condition(node, intrinsics)

    return TypeVizItemTreeNodeTypeNode(node_expression, node_name, node_condition)


def _natvis_node_parse_tree_items(item_node, intrinsics):
    item_condition = _natvis_node_parse_condition(item_node, intrinsics)
    item_optional = _natvis_node_parse_optional(item_node)

    items_size = _natvis_node_parse_size_node(item_node, intrinsics)
    # size can be omitted

    item_head_pointer = _natvis_node_parse_tree_head_pointer(item_node, intrinsics)
    if item_head_pointer is None:
        return None

    item_left_pointer = _natvis_node_parse_tree_child_pointer(item_node, 'LeftPointer', intrinsics)
    if item_left_pointer is None:
        return None

    item_right_pointer = _natvis_node_parse_tree_child_pointer(item_node, 'RightPointer', intrinsics)
    if item_right_pointer is None:
        return None

    items_value_node = _natvis_node_parse_tree_value_node(item_node, intrinsics)
    if items_value_node is None:
        return None

    return TypeVizItemProviderTreeItems(items_size, item_head_pointer,
                                        item_left_pointer, item_right_pointer,
                                        items_value_node,
                                        item_condition, item_optional)


def _natvis_node_parse_condition(node, intrinsics):
    return _natvis_node_parse_expression(node.attrib.get('Condition'), intrinsics)


def _natvis_node_parse_optional(node):
    return node.attrib.get('Optional', 'false') == 'true'


def _natvis_node_parse_intrinsic(node, intrinsics):
    name = _unescape(node.attrib['Name'])
    expr = _natvis_node_parse_expression(node.attrib['Expression'], intrinsics)
    return name, expr
