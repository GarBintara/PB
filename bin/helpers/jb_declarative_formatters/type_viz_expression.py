from enum import Enum, auto


class TypeVizFormatSpec(Enum):
    DECIMAL = auto()
    OCTAL = auto()
    HEX = auto()
    HEX_UPPERCASE = auto()
    HEX_NO_PREFIX = auto()
    HEX_UPPERCASE_NO_PREFIX = auto()
    BINARY = auto()
    BINARY_NO_PREFIX = auto()
    SCIENTIFIC = auto()
    SCIENTIFIC_MIN = auto()
    CHARACTER = auto()
    STRING = auto()
    STRING_NO_QUOTES = auto()
    UTF8_STRING = auto()
    UTF8_STRING_NO_QUOTES = auto()
    WIDE_STRING = auto()
    WIDE_STRING_NO_QUOTES = auto()
    UTF32_STRING = auto()
    UTF32_STRING_NO_QUOTES = auto()
    ENUM = auto()
    HEAP_ARRAY = auto()
    NO_ADDRESS = auto()
    NO_DERIVED = auto()
    NO_RAW_VIEW = auto()
    NUMERIC_RAW_VIEW = auto()
    RAW_FORMAT = auto()
    IGNORED = auto()


class TypeVizFormatOptions(object):
    def __init__(self, array_size=None, format_spec=None, view_spec=None):
        self.array_size = array_size
        self.format_spec = format_spec
        self.view_spec = view_spec

    def __str__(self):
        r = ''
        if self.array_size:
            r += " as array[{}]".format(self.array_size)
        if self.format_spec:
            r += " as {}".format(self.format_spec.name)
        if self.view_spec:
            r += " using view {}".format(self.view_spec)
        return r

    def __repr__(self):
        r = ''
        if self.array_size:
            r += "[{}]".format(self.array_size)
        if self.format_spec:
            r += "{}".format(self.format_spec.name)
        if self.view_spec:
            r += " {}".format(self.view_spec)
        return r

    def __eq__(self, other):
        if not isinstance(other, TypeVizFormatOptions):
            return False
        if self.array_size != other.array_size:
            return False
        if self.format_spec != other.format_spec:
            return False
        if self.view_spec != other.view_spec:
            return False
        return True


class TypeVizExpression(object):
    def __init__(self, text, array_size=None, format_spec=None, view_spec=None):
        self.text = text
        self.view_options = TypeVizFormatOptions(array_size, format_spec, view_spec)

    def __str__(self):
        r = "'{}'{}".format(self.text, self.view_options)
        return r

    def __repr__(self):
        return repr(self.__dict__)

    def __eq__(self, other):
        if not isinstance(other, TypeVizExpression):
            return False
        if self.text != other.text:
            return False
        if self.view_options != other.view_options:
            return False
        return True

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.text, self.view_options))


class TypeVizInterpolatedString(object):
    def __init__(self, fmt, fmt_expr_list):
        self.fmt = fmt
        self.expr_list = fmt_expr_list

    def __str__(self):
        return self.fmt.format(*self.expr_list)

    def __repr__(self):
        return repr(self.__dict__)

    def __eq__(self, other):
        if not isinstance(other, TypeVizInterpolatedString):
            return False
        return self.fmt == other.fmt and self.expr_list == other.expr_list

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.fmt, self.expr_list))
