from enum import Enum, auto

from jb_declarative_formatters.type_name_template import TypeNameTemplate
from six import StringIO


class TypeNameParsingError(Exception):
    def __init__(self, stream, pos, message) -> None:
        super(TypeNameParsingError, self).__init__('"{}":{}: {}'.format(stream, pos, message))
        self.stream = stream
        self.pos = pos


class DefaultDiagHandler(object):
    def raise_error(self, error):
        raise error


def parse_type_name_template(type_name, diag_handler=None):
    diag_handler = diag_handler or DefaultDiagHandler()
    lexer = Lexer(type_name, diag_handler)
    parser = Parser(lexer, diag_handler)
    return parser.parse_type_name()


class TokenType(Enum):
    UNKNOWN = auto()
    END = auto(),
    IDENT = auto(),
    LESS = auto(),
    GREATER = auto(),
    COMMA = auto(),
    MUL = auto(),


class Token(object):
    def __init__(self, tt, text, pos, spaces_before):
        self.tt = tt
        self.text = text
        self.pos = pos
        self.spaces_before = spaces_before

    def __str__(self):
        if self.text:
            return self.text
        return self.tt.name


class Lexer(object):
    WHITESPACES = [' ', '\n', '\t']
    TT_MAP = {'<': TokenType.LESS, '>': TokenType.GREATER, ',': TokenType.COMMA, '*': TokenType.MUL}

    def __init__(self, characters, diag_handler):
        self.stream = characters
        self.stream_len = len(self.stream)
        self.diag_handler = diag_handler
        self.pos = 0

    def fetch(self):
        # skip whitespaces
        spaces_start_pos = self.pos
        while self.pos < self.stream_len and self.stream[self.pos] in self.WHITESPACES:
            self.pos += 1
        spaces = self.pos - spaces_start_pos
        if self.pos >= self.stream_len:
            return Token(TokenType.END, '', self.pos, spaces)

        tok_start_pos = self.pos
        c = self.stream[self.pos]
        self.pos += 1
        if c in self.TT_MAP:
            tt = self.TT_MAP[c]
            return Token(tt, c, tok_start_pos, spaces)

        # interprete anything else as identifier
        while self.pos < self.stream_len:
            c = self.stream[self.pos]
            if c in self.WHITESPACES:
                break
            if c in self.TT_MAP:
                break
            self.pos += 1

        ident = self.stream[tok_start_pos:self.pos]
        return Token(TokenType.IDENT, ident, tok_start_pos, spaces)

    def _raise_error(self, message):
        self.diag_handler.raise_error(self._make_error(message))

    def _make_error(self, message):
        return TypeNameParsingError(self.stream, self.pos, message)


class Parser(object):
    def __init__(self, lexer, diag_handler):
        self.lexer = lexer
        self.diag_handler = diag_handler
        self.token = None
        self.advance()

    def advance(self):
        self.token = self.lexer.fetch()

    def tt(self):
        return self.token.tt

    def raise_error(self, *args, **kwargs):
        self.diag_handler.raise_error(args, kwargs)

    def parse_type_name(self):
        ident = self._parse_type_name_template()
        if self.tt() != TokenType.END:
            self._raise_unexpected_token_error('<END>')
        return ident

    def _parse_type_name_template(self):
        ident = StringIO()
        fmt = StringIO()
        args = []

        while True:
            if self.tt() == TokenType.IDENT:
                name = self._parse_name()
                ident.write(name)
                fmt.write(name)

                if self.tt() == TokenType.LESS:
                    ident.write(self.token.text)
                    fmt.write(self.token.text)

                    args_part, args_fmt = self._parse_type_list()

                    # write format string to substitute template arguments
                    if args_part:
                        fmt.write(args_fmt)
                        args.extend(args_part)

                    if self.tt() != TokenType.GREATER:
                        self._raise_unexpected_token_error('\'>\'')

                    ident.write(self.token.text)
                    fmt.write(self.token.text)

                    self.advance()

                    ident.write(' ' * self.token.spaces_before)
                    fmt.write(' ' * self.token.spaces_before)

                continue

            if self.tt() == TokenType.MUL:
                ident.write(self.token.text)
                fmt.write(self.token.text)

                self.advance()

                ident.write(' ' * self.token.spaces_before)
                fmt.write(' ' * self.token.spaces_before)

                continue

            break

        return TypeNameTemplate(ident.getvalue(), fmt.getvalue(), args)

    def _parse_name(self):
        ident = self.token.text
        self.advance()
        while self.tt() == TokenType.MUL or self.tt() == TokenType.IDENT:
            ident += ' ' * self.token.spaces_before + self.token.text
            self.advance()
        ident += ' ' * self.token.spaces_before
        return ident

    def _parse_type_list(self):
        # assert cur token is '<'
        self.advance()

        args = []
        fmt = StringIO()

        # handle <> as special case
        if self.tt() == TokenType.GREATER:
            fmt.write(' ' * self.token.spaces_before)
            return args, fmt.getvalue()

        # parse <type|*[,...]
        spaces_before_type_name = self.token.spaces_before
        cur_type = self._parse_type_name_or_wildcard()
        if not cur_type.is_wildcard:
            fmt.write(' ' * spaces_before_type_name)
        args.append(cur_type)
        fmt.write('{}')

        while self.tt() == TokenType.COMMA:
            fmt.write(',')
            self.advance()

            cur_type = self._parse_type_name_or_wildcard()
            args.append(cur_type)
            fmt.write('{}')

        if self.tt() != TokenType.GREATER:
            self._raise_unexpected_token_error('\',\' or \'>\'')

        return args, fmt.getvalue()

    def _parse_type_name_or_wildcard(self):
        if self.tt() == TokenType.MUL:
            # ignore spaces before wildcard
            ident = self.token.text
            self.advance()
            return TypeNameTemplate(ident)

        return self._parse_type_name_template()

    def _raise_unexpected_token_error(self, expected_message):
        self._raise_error('Unexpected token \'{}\', expected {}'.format(self.token, expected_message))

    def _raise_error(self, message):
        self.diag_handler.raise_error(self._make_error(message))

    def _make_error(self, message):
        return TypeNameParsingError(self.lexer.stream, self.token.pos, message)
