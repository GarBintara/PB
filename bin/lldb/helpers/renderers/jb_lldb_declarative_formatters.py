import importlib
import inspect
import re
import shlex
import traceback
from six import StringIO

import lldb

from jb_declarative_formatters import *
from jb_declarative_formatters.parsers.type_name_parser import parse_type_name_template
from .jb_lldb_logging import log
from .jb_lldb_utils import register_lldb_commands, make_absolute_name
from .jb_lldb_declarative_formatters_loaders import type_viz_loader_add, type_viz_loader_remove, \
    type_viz_loader_get_list, type_viz_loader_get, TypeVizLoaderException
from .jb_lldb_declarative_formatters_options import g_max_num_children, g_force_suppress_errors, g_max_recursion_level
from .jb_lldb_declarative_formatters_manager import FormattersManager

lldb_formatters_manager = None

g_recursion_level = 0


def make_recursion_safe_func(fn, cb_on_fail):
    def safe_func(*args, **kwargs):
        global g_recursion_level
        if g_recursion_level > g_max_recursion_level:
            return cb_on_fail()

        try:
            g_recursion_level += 1
            return fn(*args, **kwargs)
        finally:
            g_recursion_level -= 1

    return safe_func


###############################################################################
# LLDB module entry point
###############################################################################
def __lldb_init_module(debugger, internal_dict):
    log('JetBrains declarative formatters LLDB module registered into {}', str(debugger))

    commands_list = {
        make_absolute_name(__name__, '_cmd_loaders_add'): 'jb_renderers_loaders_add',
        make_absolute_name(__name__, '_cmd_loaders_remove'): 'jb_renderers_loaders_remove',
        make_absolute_name(__name__, '_cmd_loaders_list'): 'jb_renderers_loaders_list',

        make_absolute_name(__name__, '_cmd_load'): 'jb_renderers_load',
        make_absolute_name(__name__, '_cmd_remove'): 'jb_renderers_remove',
        make_absolute_name(__name__, '_cmd_reload'): 'jb_renderers_reload',
        make_absolute_name(__name__, '_cmd_unload'): 'jb_renderers_unload',

        make_absolute_name(__name__, '_cmd_reload_all'): 'jb_renderers_reload_all',
        make_absolute_name(__name__, '_cmd_unload_all'): 'jb_renderers_unload_all',
        make_absolute_name(__name__, '_cmd_remove_all'): 'jb_renderers_remove_all',
    }
    register_lldb_commands(debugger, commands_list)

    summary_func_name = '{}.declarative_summary'.format(__name__)
    synth_class_name = '{}.DeclarativeSynthProvider'.format(__name__)
    global lldb_formatters_manager
    lldb_formatters_manager = FormattersManager(summary_func_name, synth_class_name)


def get_max_string_summary_length(debugger):
    debugger_name = debugger.GetInstanceName()
    max_len = int(lldb.SBDebugger.GetInternalVariableValue("target.max-string-summary-length",
                                                           debugger_name).GetStringAtIndex(0))
    return max_len


###############################################################################
# Viz loaders commands
###############################################################################
def _cmd_loaders_add(debugger, command, exe_ctx, result, internal_dict):
    # raise NotImplementedError("jb_renderers_loaders_add is not implemented yet")
    HELP_STR = 'Usage: jb_renderers_loaders_add <loader_tag> <module> <funcname>'
    cmd = shlex.split(command)
    if len(cmd) < 1:
        result.SetError(
            'Loader tag expected.\n{}'.format(HELP_STR))
        return
    tag = cmd[0]
    cmd = cmd[1:]
    if len(cmd) < 1:
        result.SetError(
            'Python module expected.\n{}'.format(HELP_STR))
        return
    module = cmd[0]

    try:
        mod = importlib.import_module(module)
    except Exception as e:
        result.SetError(str(e))
        return

    cmd = cmd[1:]
    if len(cmd) < 1:
        result.SetError(
            'Function name expected.\n{}'.format(HELP_STR))
        return
    func_name = cmd[0]

    funcs = inspect.getmembers(mod, lambda m: inspect.isfunction(m) and m.__name__ == func_name)
    if funcs is None or len(funcs) == 0:
        result.SetError(
            'Can\'t find loader function {} in module {}'.format(func_name, mod))
        return

    if len(funcs) != 1:
        result.SetError(
            'Loader function {} in module {} is ambiguous'.format(func_name, mod))
        return

    _, func = funcs[0]
    type_viz_loader_add(tag, func)


def _cmd_loaders_remove(debugger, command, exe_ctx, result, internal_dict):
    HELP_STR = 'Usage: jb_renderers_loaders_remove <loader_tag>'
    cmd = shlex.split(command)
    if len(cmd) < 1:
        result.SetError(
            'Loader tag expected.\n{}'.format(HELP_STR))
        return

    tag = cmd[0]
    type_viz_loader_remove(tag)


def _cmd_loaders_list(debugger, command, exe_ctx, result, internal_dict):
    lst = type_viz_loader_get_list()
    lst_view = {tag: func.__module__ + '.' + func.__name__ for tag, func in lst.items()}
    result.AppendMessage(str(lst_view))


###############################################################################
# Formatters related commands
###############################################################################
def _cmd_load(debugger, command, exe_ctx, result, internal_dict):
    HELP_STR = 'Usage: jb_renderers_load tag <loader_tag> <natvis_file_path>...'
    cmd = shlex.split(command)
    if len(cmd) < 1:
        result.SetError(
            'Loader tag expected.\n{}'.format(HELP_STR))
        return
    tag = cmd[0]
    try:
        loader = type_viz_loader_get(tag)
    except KeyError:
        result.SetError(
            'Unknown loader tag {}'.format(tag))
        return

    filepaths = cmd[1:]
    for filepath in filepaths:
        try:
            lldb_formatters_manager.register(debugger, filepath, loader)
        except TypeVizLoaderException as e:
            result.SetError('{}'.format(str(e)))
            return


def _cmd_remove(debugger, command, exe_ctx, result, internal_dict):
    HELP_STR = 'Usage: jb_renderers_remove <vis_file_path>...'
    cmd = shlex.split(command)
    if len(cmd) < 1:
        result.SetError(
            'At least one file expected.\n{}'.format(HELP_STR))
        return

    remove_file_list(debugger, cmd)


def _cmd_reload(debugger, command, exe_ctx, result, internal_dict):
    HELP_STR = 'Usage: jb_renderers_reload <vis_file_path>...'
    cmd = shlex.split(command)
    if len(cmd) < 1:
        result.SetError(
            'At least one file expected.\n{}'.format(HELP_STR))
        return

    reload_file_list(debugger, cmd)


def _cmd_unload(debugger, command, exe_ctx, result, internal_dict):
    HELP_STR = 'Usage: jb_renderers_unload <vis_file_path>...'
    cmd = shlex.split(command)
    if len(cmd) < 1:
        result.SetError(
            'At least one file expected.\n{}'.format(HELP_STR))
        return

    unload_file_list(debugger, cmd)


def _cmd_remove_all(debugger, command, exe_ctx, result, internal_dict):
    remove_all(debugger)


def _cmd_reload_all(debugger, command, exe_ctx, result, internal_dict):
    reload_all(debugger)


def _cmd_unload_all(debugger, command, exe_ctx, result, internal_dict):
    unload_all(debugger)


def remove_all(debugger):
    files = lldb_formatters_manager.get_all_registered_files()
    remove_file_list(debugger, files)


def reload_all(debugger):
    files = lldb_formatters_manager.get_all_registered_files()
    reload_file_list(debugger, files)


def unload_all(debugger):
    files = lldb_formatters_manager.get_all_registered_files()
    unload_file_list(debugger, files)


def remove_file_list(debugger, files):
    for filepath in files:
        lldb_formatters_manager.unregister(debugger, filepath)


def unload_file_list(debugger, files):
    for filepath in files:
        lldb_formatters_manager.unload(debugger, filepath)


def reload_file_list(debugger, files):
    for filepath in files:
        lldb_formatters_manager.reload(debugger, filepath)


###############################################################################
# Formatters
###############################################################################
class EvaluateError(Exception):
    def __init__(self, error):
        super(Exception, self).__init__(str(error))


class IgnoreSynthProvider(Exception):
    def __init__(self, msg=None):
        super(Exception, self).__init__(str(msg) if msg else None)


def declarative_summary(valobj, internal_dict):
    try:
        return declarative_summary_impl(valobj, internal_dict)
    except IgnoreSynthProvider:
        return ''
    except:
        if not g_force_suppress_errors:
            raise
        return ''


def declarative_summary_impl(valobj, internal_dict):
    valobj_non_synth = valobj.GetNonSyntheticValue()
    log("Retrieving summary of value named '{}'...", valobj_non_synth.GetName())

    viz_candidates, type_name_template, type_name, valobj_non_synth = _try_get_matched_vizualizers(
        valobj_non_synth.GetType(),
        valobj_non_synth)
    if not viz_candidates:
        raise Exception("Can't find any visualizers: inconsistent type matching for {} (template: {})"
                        .format(type_name, type_name_template))

    for name_viz_pair in viz_candidates:
        viz, type_viz_name = name_viz_pair
        try:
            res = _try_evaluate_summary(valobj_non_synth, viz, type_viz_name, type_name_template)
        except EvaluateError:
            continue
        return res

    # no candidates
    log("No matching display string candidate found")
    return ''


def _try_evaluate_summary(valobj_non_synth, viz, type_viz_name, type_name_template):
    log("Trying vizualizer for type '{}'...", str(type_viz_name))

    if not viz.summaries:
        log('No user provided summary found, return default...')
        return ''

    wildcard_matches = _match_type_viz_template(type_viz_name.type_name_template, type_name_template)

    # try to choose candidate from ordered display string expressions
    summary_str = _find_first_good_node(viz.summaries, _process_summary_node, valobj_non_synth, wildcard_matches)
    # if no valid summary found return empty string
    return summary_str if summary_str else ''


def _try_get_matched_vizualizers(valobj_type, valobj_non_synth):
    valobj_type = valobj_type.GetUnqualifiedType()
    valobj_type_name = valobj_type.GetName()
    log("Trying to find visualizer for type: '{}'...", valobj_type_name)
    try:
        type_name_template = parse_type_name_template(valobj_type_name)
    except Exception as e:
        log('Parsing typename {} failed: {}', valobj_type_name, e)
        raise

    viz_candidates = _get_matched_type_visualizers(type_name_template)
    if not viz_candidates:
        if valobj_type.IsTypedefType():
            valobj_typedefed_type = valobj_type.GetTypedefedType()
            valobj_typedefed_type_name = valobj_typedefed_type.GetName()
            log("Type '{}' is typedef to type '{}'", valobj_type_name, valobj_typedefed_type_name)
            if valobj_typedefed_type_name != valobj_type_name:
                return _try_get_matched_vizualizers(valobj_typedefed_type, valobj_non_synth)

        if valobj_type.IsPointerType():
            ptr_val = valobj_non_synth.GetValueAsUnsigned()
            if ptr_val == 0:
                raise IgnoreSynthProvider("Ignore vizualizers for nullptr values")

        if valobj_type.IsPointerType() or valobj_type.IsReferenceType():
            # strip pointer or reference from type and value
            valobj_deref_non_synth = valobj_non_synth.Dereference().GetNonSyntheticValue()
            valobj_deref_type = valobj_deref_non_synth.GetType().GetUnqualifiedType()
            valobj_deref_type_name = valobj_deref_type.GetName()
            log("Type '{}' is pointer or reference: going to decayed type '{}'...", valobj_type_name,
                valobj_deref_type_name)
            if valobj_deref_type_name != valobj_type_name:
                return _try_get_matched_vizualizers(valobj_deref_type, valobj_deref_non_synth)

    return viz_candidates, type_name_template, valobj_type_name, valobj_non_synth


def _match_type_viz_template(type_viz_type_name_template, type_name_template):
    wildcard_matches = []
    if not type_viz_type_name_template.match(type_name_template, wildcard_matches):
        raise Exception("Inconsistent type matching: can't match template {} with {}"
                        .format(type_name_template, type_viz_type_name_template))

    wildcard_matches = _fix_wildcard_matches(wildcard_matches)
    return wildcard_matches


def optional_node_processor(fn):
    def wrapped(node, *args, **kwargs):
        assert isinstance(node, TypeVizItemOptionalNodeMixin)
        try:
            return fn(node, *args, **kwargs)
        except EvaluateError:
            if not node.optional:
                raise

        return None

    return wrapped


def _evaluate_interpolated_string(interp_string, ctx_val, wildcards):
    assert isinstance(interp_string, TypeVizInterpolatedString)
    substrings = []
    for expr in interp_string.expr_list:
        expr_text = _resolve_wildcards(expr.text, wildcards)
        expr_opts = expr.view_options
        substring = _eval_display_string_expression(ctx_val, expr_text, expr_opts) or ''
        substrings.append(substring)

    return interp_string.fmt.format(*substrings)


def _on_process_summary_node_recursion_level_exceeded():
    log("Error: "
        "Elements of visualizer has been disabled "
        "because the recursion level exceeds the maximum supported limit of {}.  "
        "Check your visualizer entries for circular references.", g_max_recursion_level)
    return ''


@optional_node_processor
def _process_summary_node(summary, ctx_val, wildcards):
    assert isinstance(summary, TypeVizSummary)
    if summary.condition:
        condition = _resolve_wildcards(summary.condition, wildcards)
        if not _process_node_condition(condition, ctx_val):
            return None

    eval_fn = make_recursion_safe_func(_evaluate_interpolated_string,
                                       _on_process_summary_node_recursion_level_exceeded)
    return eval_fn(summary.value, ctx_val, wildcards)


def _get_matched_type_visualizers(type_name_template):
    result = []
    for type_viz_storage in lldb_formatters_manager.get_all_type_viz():
        result.extend([name_match_pair for name_match_pair in type_viz_storage.get_matched_types(type_name_template)])
    return result


def _fix_wildcard_matches(matches):
    # remove breaking type prefixes from typenames
    def _remove_type_prefix(typename):
        prefix_list = ['struct ', 'class ']
        for prefix in prefix_list:
            if typename.startswith(prefix):
                typename = typename[len(prefix):]
        return typename

    return [_remove_type_prefix(str(t)) for t in matches]


class DeclarativeSynthProvider(object):

    # FOR THE GLORY OF HACKS
    def __new__(cls, valobj, internal_dict):
        try:
            obj = super(DeclarativeSynthProvider, cls).__new__(cls)

            obj.valobj = valobj
            obj.viz = None
            obj.child_providers = None
            obj.child_providers_start_index = None

            obj._update(True)

        except IgnoreSynthProvider:
            # valid exception to skip provider and show raw-view
            return None

        except Exception as e:
            # some unexpected error happened
            if not g_force_suppress_errors:
                log("{}", traceback.format_exc())
            return None

        return obj

    def __init__(self, valobj, internal_dict):
        pass

    def update(self):
        # Force do nothing on update
        return False

    def _update(self, is_initial):
        valobj_non_synth = self.valobj.GetNonSyntheticValue()
        log("*" * 80)
        log("{} children of value named '{}'...",
            is_initial and "Initial retrieving" or "Updating",
            valobj_non_synth.GetName())

        viz_candidates, type_name_template, type_name, valobj_non_synth = _try_get_matched_vizualizers(
            valobj_non_synth.GetType(),
            valobj_non_synth)
        if not viz_candidates:
            raise Exception("Can't find any visualizers: inconsistent type matching for {} (template: {})"
                            .format(type_name, type_name_template))

        viz = None
        for name_viz_pair in viz_candidates:
            viz, type_viz_name = name_viz_pair
            try:
                self.child_providers, self.child_providers_start_index = _try_update_child_providers(
                    valobj_non_synth,
                    viz, type_viz_name,
                    type_name_template)
            except EvaluateError:
                continue

            break

        if not viz:
            log("No viz matched for for {}", type_name)
            raise IgnoreSynthProvider()

        self.viz = viz

    def num_children(self):
        return sum(
            child_prov.num_children() for child_prov in self.child_providers) if self.child_providers else 0

    def has_children(self):
        has_children = self.viz and bool(self.viz.item_providers)
        return has_children

    def get_child_index(self, name):
        if not self.child_providers:
            return -1

        for prov in self.child_providers:
            try:
                index = prov.get_child_index(name)
            except Exception as e:
                # some unexpected error happened
                if not g_force_suppress_errors:
                    raise
                return -1

            if index != -1:
                return index

        return -1

    def get_child_at_index(self, index):
        if not self.child_providers:
            return None

        child_provider, relative_index = self._find_child_provider(index)
        if not child_provider:
            return None
        try:
            return child_provider.get_child_at_index(relative_index)
        except Exception as e:
            # some unexpected error happened
            if not g_force_suppress_errors:
                raise
            return None

    def _find_child_provider(self, index):
        # TODO: binary search, not linear
        for i, start_idx in enumerate(self.child_providers_start_index):
            if start_idx > index:
                # return previous provider
                prov_index = i - 1
                break
        else:
            # last provider
            prov_index = len(self.child_providers) - 1

        if prov_index == -1:
            return None, index

        prov = self.child_providers[prov_index]
        child_start_idx = self.child_providers_start_index[prov_index]

        return prov, (index - child_start_idx)


def _try_update_child_providers(valobj_non_synth, viz, type_viz_name, type_name_template):
    log("Trying vizualizer for type '{}'...", str(type_viz_name))

    wildcard_matches = _match_type_viz_template(type_viz_name.type_name_template, type_name_template)

    child_providers = _build_child_providers(viz.item_providers, valobj_non_synth,
                                             wildcard_matches) if viz.item_providers else None
    child_providers_start_index = None

    if child_providers:
        start_idx = 0
        child_providers_start_index = []
        for prov in child_providers:
            child_providers_start_index.append(start_idx)
            start_idx += prov.num_children()

    return child_providers, child_providers_start_index


def _check_condition(val, condition):
    res = _eval_expression(val, '(bool)(' + condition + ')', None)
    if not res.GetValueAsUnsigned():
        return False
    return True


TEMPLATE_REGEX = re.compile(r'\$T([1-9][0-9]*)')


def _resolve_wildcards(expr, wildcards):
    expr_len = len(expr)
    i = 0
    s = StringIO()
    while i < expr_len:
        m = TEMPLATE_REGEX.search(expr, i)
        if m is None:
            s.write(expr[i:])
            break

        s.write(m.string[i:m.start()])
        wildcard_idx = int(m.group(1)) - 1
        try:
            replacement = wildcards[wildcard_idx]
        except IndexError:
            replacement = m.string[m.start():m.end()]
        s.write(replacement)
        i = m.end()
        if i < expr_len and replacement and replacement[-1] == '>' and expr[i] == '>':
            # write extra space between >>
            s.write(' ')

    return s.getvalue()


def _eval_expression(val, expr, value_name):
    log("Evaluate {} in context of {} of {}", expr, val.GetName(), val.GetTypeName())

    options = lldb.SBExpressionOptions()
    options.SetSuppressPersistentResult(True)
    options.SetFetchDynamicValue(lldb.eDynamicDontRunTarget)
    result = val.EvaluateExpression(expr, options, value_name)
    if result is None:
        err = lldb.SBError()
        err.SetErrorString("evaluation setup failed")
        log("Evaluate failed: {}", str(err))
        raise EvaluateError(err)

    result_non_synth = result.GetNonSyntheticValue()
    err = result_non_synth.GetError()
    if err.Fail():
        log("Evaluate failed: {}", str(err))
        raise EvaluateError(err)

    log("Evaluate succeed: result type - {}", str(result_non_synth.GetTypeName()))
    return result


TYPE_VIZ_FORMAT_SPEC_TO_LLDB_FORMAT_MAP = {
    TypeVizFormatSpec.DECIMAL: lldb.eFormatDecimal,
    TypeVizFormatSpec.OCTAL: lldb.eFormatOctal,
    TypeVizFormatSpec.HEX: lldb.eFormatHex,
    TypeVizFormatSpec.HEX_UPPERCASE: lldb.eFormatHexUppercase,
    TypeVizFormatSpec.HEX_NO_PREFIX: lldb.eFormatHex,
    TypeVizFormatSpec.HEX_UPPERCASE_NO_PREFIX: lldb.eFormatHexUppercase,
    TypeVizFormatSpec.BINARY: lldb.eFormatBinary,
    TypeVizFormatSpec.BINARY_NO_PREFIX: lldb.eFormatBinary,
    TypeVizFormatSpec.SCIENTIFIC: lldb.eFormatFloat,  # TODO
    TypeVizFormatSpec.SCIENTIFIC_MIN: lldb.eFormatFloat,  # TODO
    TypeVizFormatSpec.CHARACTER: lldb.eFormatChar,
    # TypeVizFormatSpec.STRING: lldb.eFormatCString,
    # TypeVizFormatSpec.STRING_NO_QUOTES: lldb.eFormatCString,
    # TypeVizFormatSpec.UTF8_STRING: lldb.eFormatCString,
    # TypeVizFormatSpec.UTF8_STRING_NO_QUOTES: lldb.eFormatCString,
    # TypeVizFormatSpec.WIDE_STRING: lldb.eFormatDefault,  # TODO
    # TypeVizFormatSpec.WIDE_STRING_NO_QUOTES: lldb.eFormatDefault,  # TODO
    # TypeVizFormatSpec.UTF32_STRING: lldb.eFormatDefault,  # TODO
    # TypeVizFormatSpec.UTF32_STRING_NO_QUOTES: lldb.eFormatDefault,  # TODO
    TypeVizFormatSpec.ENUM: lldb.eFormatEnum,
    TypeVizFormatSpec.HEAP_ARRAY: lldb.eFormatDefault,  # TODO
    TypeVizFormatSpec.NO_ADDRESS: lldb.eFormatDefault,  # TODO
    TypeVizFormatSpec.NO_DERIVED: lldb.eFormatDefault,  # TODO
    TypeVizFormatSpec.NO_RAW_VIEW: lldb.eFormatDefault,  # TODO
    TypeVizFormatSpec.NUMERIC_RAW_VIEW: lldb.eFormatDefault,  # TODO
    TypeVizFormatSpec.RAW_FORMAT: lldb.eFormatDefault,  # TODO
    TypeVizFormatSpec.IGNORED: lldb.eFormatDefault,
}

BASIC_CHAR_TYPES = (lldb.eBasicTypeChar,
                    lldb.eBasicTypeSignedChar,
                    lldb.eBasicTypeUnsignedChar,
                    lldb.eBasicTypeWChar,
                    lldb.eBasicTypeSignedWChar,
                    lldb.eBasicTypeUnsignedWChar,
                    lldb.eBasicTypeChar16,
                    lldb.eBasicTypeChar32)

TYPE_VIZ_FORMAT_SPEC_STRING_INFO = {
    TypeVizFormatSpec.STRING: (1, True),
    TypeVizFormatSpec.STRING_NO_QUOTES: (1, False),
    TypeVizFormatSpec.UTF8_STRING: (1, True),
    TypeVizFormatSpec.UTF8_STRING_NO_QUOTES: (1, False),
    TypeVizFormatSpec.WIDE_STRING: (2, True),
    TypeVizFormatSpec.WIDE_STRING_NO_QUOTES: (2, False),
    TypeVizFormatSpec.UTF32_STRING: (4, True),
    TypeVizFormatSpec.UTF32_STRING_NO_QUOTES: (4, True),
}


def _apply_value_formatting(val, format_spec, size):
    if size is not None:
        val_non_synth = val.GetNonSyntheticValue()
        val_type = val_non_synth.GetType()
        if val_type.IsPointerType():
            elem_type = val_type.GetPointeeType()
        elif val_type.IsArrayType():
            elem_type = val_type.GetArrayElementType()
            val_non_synth = val_non_synth.AddressOf()
        else:
            elem_type = None

        if elem_type:
            upd_val_type = elem_type.GetArrayType(size).GetPointerType()
            new_val = val_non_synth.Cast(upd_val_type)
            val = new_val.Dereference()

    if format_spec is not None:
        lldb_fmt = TYPE_VIZ_FORMAT_SPEC_TO_LLDB_FORMAT_MAP.get(format_spec, None)
        if lldb_fmt is not None:
            val.SetFormat(lldb_fmt)

    return val


def _extract_string_from_value(val, char_size, quote=True, max_size=None):
    zero_required = False
    if max_size is None:
        max_size = get_max_string_summary_length(val.GetTarget().GetDebugger())
        zero_required = True

    ofs = 0
    chunk_size = max_size
    res = ''
    zero_found = False
    if quote:
        if char_size == 1:
            res = '"'
        elif char_size == 2:
            res = 'L"'
        elif char_size == 4:
            res = 'U"'
        else:
            return None

    while ofs < max_size:
        data = None
        while chunk_size != 0:
            data = val.GetPointeeData(ofs, min(chunk_size, max_size - ofs))
            if data is not None:
                try:
                    _ = data.uint8[0]
                    break
                except:
                    chunk_size //= 2

        if chunk_size == 0:
            return None

        if char_size == 1:
            chars = data.uint8
        elif char_size == 2:
            chars = data.uint16
        elif char_size == 4:
            chars = data.uint32
        else:
            return None

        for i in range(0, chunk_size):
            ch = chars[i]
            if ch == 0:
                zero_found = True
                break
            res += chr(ch)

        if zero_found:
            break
        ofs += chunk_size

    if zero_found or not zero_required:
        res += '"' if quote else ''
    else:
        res += '"...' if quote else '...'

    return res


def _get_value_primitive_string_elem_type(val_non_synth):
    val_type = val_non_synth.GetType()
    if val_type.IsPointerType():
        elem_type = val_type.GetPointeeType()
    elif val_type.IsArrayType():
        elem_type = val_type.GetArrayElementType()
    else:
        # value is neither array, nor pointer
        return None

    basic_elem_type = elem_type.GetBasicType()
    return elem_type if basic_elem_type in BASIC_CHAR_TYPES else None


def _apply_post_value_formatting(val, display_string, format_spec, size):
    format_spec_string_info = TYPE_VIZ_FORMAT_SPEC_STRING_INFO.get(format_spec, None)
    if format_spec_string_info is None and size is not None:
        val_non_synth = val.GetNonSyntheticValue()
        elem_type = _get_value_primitive_string_elem_type(val_non_synth)
        if elem_type is not None:
            display_string = _extract_string_from_value(val_non_synth, elem_type.GetByteSize(),
                                                        quote=True, max_size=size)

    if format_spec_string_info:
        char_size, quote_string = format_spec_string_info
        val_non_synth = val.GetNonSyntheticValue()
        val_type = val_non_synth.GetType()
        if val_type.IsPointerType():
            display_string = _extract_string_from_value(val_non_synth, char_size, quote_string, size)
        elif val_type.IsArrayType():
            display_string = _extract_string_from_value(val_non_synth.AddressOf(), char_size, quote_string, size)

    elif format_spec is not None:
        display_string = _apply_formatting_specifiers_post_proc(val, display_string, format_spec)

    return display_string


def _apply_formatting_specifiers_post_proc(value, display_string, format_spec):
    if format_spec == TypeVizFormatSpec.HEX_NO_PREFIX:
        if len(display_string) > 2 and display_string[0:2] == '0x':
            return display_string[2:]
        return display_string

    if format_spec == TypeVizFormatSpec.HEX_UPPERCASE_NO_PREFIX:
        if len(display_string) > 2 and display_string[0:2] == '0x':
            return display_string[2:].upper()
        return display_string.upper()

    if format_spec == TypeVizFormatSpec.BINARY_NO_PREFIX:
        if len(display_string) > 2 and display_string[0:2] == '0b':
            return display_string[2:]
        return display_string

    return display_string


def _eval_display_string_expression(ctx, expr, opts):
    result = _eval_expression(ctx, expr, None)
    size = _eval_expression_result_array_size(ctx, opts.array_size) if opts.array_size is not None else None
    result = _apply_value_formatting(result, opts.format_spec, size)
    result_non_synth = result.GetNonSyntheticValue()

    # do not request result summary if result is a pointer and some string formatting specs are present
    format_spec_string_info = TYPE_VIZ_FORMAT_SPEC_STRING_INFO.get(opts.format_spec, None)
    if result_non_synth.GetType().IsPointerType() and format_spec_string_info is not None:
        display_string = None
    else:
        display_string = result.GetSummary()

    if display_string is None:
        display_string = result.GetValue()
    else:
        # Can't apply formatting specifiers to most of synthetic summaries
        # Try to extract primitive strings where it's possible
        if not _get_value_primitive_string_elem_type(result.GetNonSyntheticValue()):
            if opts.format_spec is not None:
                log("Warning: Can't apply format specifiers '{}' for synthetic display string value",
                    opts.format_spec.name)
            if size is not None:
                log("Warning: Can't apply array size specifier with value '{}' for synthetic display string value",
                    size)
            return display_string
        # Display string is array or pointer to chars - continue standard processing flow

    if display_string is None:
        return ''
    display_string = _apply_post_value_formatting(result, display_string, opts.format_spec, size)
    if display_string is None:
        return ''
    return display_string


def _process_node_condition(condition, ctx_val):
    result = _eval_expression(ctx_val, '(bool)(' + condition + ')', None)
    if not result.GetValueAsUnsigned():
        return False
    return True


def _eval_expression_result_array_size(ctx, size_expr):
    size_value = _eval_expression(ctx, size_expr, None)
    size = size_value.GetValueAsSigned()
    if not isinstance(size, int):
        raise EvaluateError('Size value must be of integer type')
    return size


@optional_node_processor
def _node_processor_display_value(node, ctx_val, wildcards):
    assert isinstance(node, TypeVizItemConditionalNodeMixin)
    if node.condition:
        condition = _resolve_wildcards(node.condition, wildcards)
        if not _process_node_condition(condition, ctx_val):
            return None

    assert isinstance(node, TypeVizItemFormattedExpressionNodeMixin)
    expression = _resolve_wildcards(node.expr.text, wildcards)

    name = node.name if isinstance(node, TypeVizItemNamedNodeMixin) else None

    value = _eval_expression(ctx_val, expression, name)
    opts = node.expr.view_options
    size = _eval_expression_result_array_size(ctx_val, opts.array_size) if opts.array_size is not None else None
    value = _apply_value_formatting(value, opts.format_spec, size)
    return value


class SingleItemProvider(object):
    def __init__(self, value):
        self.value = value

    def num_children(self):
        return 1

    def get_child_index(self, name):
        if self.value.GetName() == name:
            return 0
        return -1

    def get_child_at_index(self, index):
        assert index == 0
        return self.value


def _process_item_provider_single(item_provider, val, wildcards):
    item_value = _node_processor_display_value(item_provider, val, wildcards)
    if not item_value:
        return None

    return SingleItemProvider(item_value)


class ExpandedItemProvider(object):
    def __init__(self, value):
        self.value = value

    def num_children(self):
        return self.value.GetNumChildren()

    def get_child_index(self, name):
        return self.value.GetIndexOfChildWithName(name)

    def get_child_at_index(self, index):
        return self.value.GetChildAtIndex(index)


def _process_item_provider_expanded(item_provider, val, wildcards):
    item_value = _node_processor_display_value(item_provider, val, wildcards)
    if not item_value:
        return None

    return ExpandedItemProvider(item_value)


def _find_first_good_node(nodes, node_proc, ctx_val, wildcards):
    # NOTE: next() can be used
    for node in nodes:
        item_value = node_proc(node, ctx_val, wildcards)
        if item_value is not None:
            return item_value
    return None


@optional_node_processor
def _node_processor_size(size_node, ctx_val, wildcards):
    assert isinstance(size_node, TypeVizItemSizeTypeNode)
    if size_node.condition:
        condition = _resolve_wildcards(size_node.condition, wildcards)
        if not _process_node_condition(condition, ctx_val):
            return None

    expression = size_node.text
    expression = _resolve_wildcards(expression, wildcards)
    value = _eval_expression(ctx_val, expression, None)
    result_value = value.GetValueAsSigned()
    if not isinstance(result_value, int):
        raise EvaluateError('Size value must be of integer type')

    return result_value


def _node_processor_array_items_value_pointer(value_pointer_node, ctx_val, wildcards):
    assert isinstance(value_pointer_node, TypeVizItemValuePointerTypeNode)
    if value_pointer_node.condition:
        condition = _resolve_wildcards(value_pointer_node.condition, wildcards)
        if not _process_node_condition(condition, ctx_val):
            return None

    expr = value_pointer_node.expr
    expression = expr.text
    opts = expr.view_options
    expression = _resolve_wildcards(expression, wildcards)
    value = _eval_expression(ctx_val, expression, None)
    size = _eval_expression_result_array_size(ctx_val, opts.array_size) if opts.array_size is not None else None
    value = _apply_value_formatting(value, opts.format_spec, size)
    return value


class ArrayItemsProvider(object):
    def __init__(self, size, value_pointer, elem_type):
        self.size = size
        self.value_pointer = value_pointer
        self.elem_type = elem_type
        self.elem_byte_size = elem_type.GetByteSize()

    def num_children(self):
        return self.size

    def get_child_index(self, name):
        try:
            return int(name.lstrip('[').rstrip(']'))
        except ValueError:
            return -1

    def get_child_at_index(self, index):
        child_name = "[{}]".format(index)
        offset = index * self.elem_byte_size
        return self.value_pointer.CreateChildAtOffset(child_name, offset, self.elem_type)


@optional_node_processor
def _node_processor_array_items(array_items_node, ctx_val, wildcards):
    assert isinstance(array_items_node, TypeVizItemProviderArrayItems)
    if array_items_node.condition:
        condition = _resolve_wildcards(array_items_node.condition, wildcards)
        if not _process_node_condition(condition, ctx_val):
            return None

    size = _find_first_good_node(array_items_node.size_nodes,
                                 _node_processor_size,
                                 ctx_val, wildcards)
    # ???
    if size is None:
        raise EvaluateError('No valid Size node found')

    value_pointer_value = _find_first_good_node(array_items_node.value_pointer_nodes,
                                                _node_processor_array_items_value_pointer,
                                                ctx_val, wildcards)
    # ???
    if value_pointer_value is None:
        raise EvaluateError('No valid ValuePointerType node found')

    value_pointer_type = value_pointer_value.GetNonSyntheticValue().GetType()
    if value_pointer_type.IsPointerType():
        elem_type = value_pointer_type.GetPointeeType()
    elif value_pointer_type.IsArrayType():
        elem_type = value_pointer_type.GetArrayElementType()
        value_pointer_value = value_pointer_value.GetNonSyntheticValue().AddressOf()
    else:
        raise EvaluateError('Value pointer is not of pointer or array type ({})'.format(str(value_pointer_type)))

    return ArrayItemsProvider(size, value_pointer_value, elem_type)


def _process_item_provider_array_items(item_provider, val, wildcards):
    return _node_processor_array_items(item_provider, val, wildcards)


def _node_processor_index_list_items_value_node(idx_str, name, index_list_value_node, ctx_val, wildcards):
    assert isinstance(index_list_value_node, TypeVizItemIndexNodeTypeNode)
    if index_list_value_node.condition:
        condition = index_list_value_node.condition.replace('$i', idx_str)
        condition = _resolve_wildcards(condition, wildcards)
        if not _process_node_condition(condition, ctx_val):
            return None

    expression = index_list_value_node.expr.text.replace('$i', idx_str)
    opts = index_list_value_node.expr.view_options
    expression = _resolve_wildcards(expression, wildcards)
    value = _eval_expression(ctx_val, expression, name)
    size = _eval_expression_result_array_size(ctx_val, opts.array_size) if opts.array_size is not None else None
    value = _apply_value_formatting(value, opts.format_spec, size)

    return value


class IndexListItemsProvider(object):
    def __init__(self, size, index_list_node, ctx_val, wildcards):
        self.size = size
        self.index_list_node = index_list_node
        self.ctx_val = ctx_val
        self.wildcards = wildcards

    def num_children(self):
        return self.size

    def get_child_index(self, name):
        try:
            return int(name.lstrip('[').rstrip(']'))
        except ValueError:
            return -1

    def get_child_at_index(self, index):
        name = "[{}]".format(index)
        value = None
        for value_node_node in self.index_list_node.value_node_nodes:
            value = _node_processor_index_list_items_value_node(str(index), name, value_node_node, self.ctx_val,
                                                                self.wildcards)
            if value:
                break

        # TODO: show some error value on None
        return value


@optional_node_processor
def _node_processor_index_list_items(index_list_node, ctx_val, wildcards):
    assert isinstance(index_list_node, TypeVizItemProviderIndexListItems)
    if index_list_node.condition:
        condition = _resolve_wildcards(index_list_node.condition, wildcards)
        if not _process_node_condition(condition, ctx_val):
            return None

    size = _find_first_good_node(index_list_node.size_nodes,
                                 _node_processor_size,
                                 ctx_val, wildcards)
    # ????
    if size is None:
        raise EvaluateError('No valid Size node found')

    return IndexListItemsProvider(size, index_list_node, ctx_val, wildcards)


def _process_item_provider_index_list_items(item_provider, val, wildcards):
    return _node_processor_index_list_items(item_provider, val, wildcards)


def _is_valid_node_ptr(node):
    if node is None:
        return False

    if not node.TypeIsPointerType():
        return False

    return True


def _get_ptr_value(node):
    val = node.GetNonSyntheticValue()
    return val.GetValueAsUnsigned() if _is_valid_node_ptr(val) else 0


class NodesProvider(object):
    def __init__(self):
        self.cache = []
        self.has_more = False
        self.names = None
        self.name2index = None


class CustomItemsProvider(object):
    def __init__(self, nodes_provider, value_expression, value_opts, wildcards):
        assert isinstance(nodes_provider, NodesProvider)

        self.nodes_cache = nodes_provider.cache
        self.has_more = nodes_provider.has_more
        self.custom_names = nodes_provider.names
        self.custom_name_to_index = nodes_provider.name2index
        self.value_expression = value_expression
        self.value_opts = value_opts
        self.wildcards = wildcards

        self.size = len(self.nodes_cache)

    def num_children(self):
        return self.size

    def get_child_index(self, name):
        if self.custom_name_to_index:
            return self.custom_name_to_index.get(name, -1)

        try:
            return int(name.lstrip('[').rstrip(']'))
        except IndexError:
            return -1

    def get_child_at_index(self, index):
        if index < 0 or index >= self.size:
            return None

        node_value = self.nodes_cache[index]
        if node_value is None:
            return None

        if self.custom_names:
            name = self.custom_names[index]
        else:
            name = "[{}]".format(index)
        value = _eval_expression(node_value, self.value_expression, name)
        opts = self.value_opts
        size = _eval_expression_result_array_size(node_value, opts.array_size) if opts.array_size is not None else None
        value = _apply_value_formatting(value, opts.format_spec, size)
        return value


class LinkedListIterator(object):
    def __init__(self, node_value, next_expression):
        self.node_value = node_value
        self.next_expression = next_expression

    def __bool__(self):
        return _get_ptr_value(self.node_value) != 0

    def __eq__(self, other):
        return _get_ptr_value(self.node_value) == _get_ptr_value(other.node_value)

    def cur_value(self):
        return self.node_value.GetNonSyntheticValue().Dereference()

    def cur_ptr(self):
        return self.node_value.GetNonSyntheticValue().GetValueAsUnsigned()

    def move_to_next(self):
        self.node_value = self._next()

    def _next(self):
        return _eval_expression(self.cur_value(), self.next_expression, None)


class LinkedListIndexedNodesProvider(NodesProvider):
    def __init__(self, size, head_pointer, next_expression):
        super(LinkedListIndexedNodesProvider, self).__init__()

        it = LinkedListIterator(head_pointer, next_expression)

        cache = []
        has_more = False

        # iterate all list nodes and cache them
        start = it.cur_ptr() if _is_valid_node_ptr(it.node_value) else 0
        max_size = size if size is not None else g_max_num_children
        idx = 0
        while it and idx < max_size:
            cache.append(it.cur_value())
            idx += 1
            it.move_to_next()

            if it and it.cur_ptr() == start:
                # check for cycled
                break

        if size is None:
            if it and idx >= max_size:
                has_more = True
        else:
            if idx < size:
                cache.extend([None] * (size - idx))

        self.cache = cache
        self.has_more = has_more
        self.names = None
        self.name2index = None


class LinkedListCustomNameNodesProvider(NodesProvider):
    def __init__(self, size, head_pointer, next_expression, custom_value_name, wildcards):
        super(LinkedListCustomNameNodesProvider, self).__init__()

        it = LinkedListIterator(head_pointer, next_expression)

        cache = []
        has_more = False
        names = []
        name2index = {}

        # iterate all list nodes and cache them
        max_size = size if size is not None else g_max_num_children
        idx = 0
        start = it
        while it and idx < max_size:
            cur_val = it.cur_value()
            name = _evaluate_interpolated_string(custom_value_name, cur_val, wildcards)
            names.append(name)
            name2index[name] = idx

            cache.append(cur_val)
            idx += 1
            it.move_to_next()

            if it == start:
                # check for cycled
                break

        if size is None:
            if it and idx >= max_size:
                has_more = True
        else:
            if idx < size:
                cache.extend([None] * (size - idx))

        self.cache = cache
        self.has_more = has_more
        self.names = names
        self.name2index = name2index


def _node_processor_linked_list_items_head_pointer(head_pointer_node, ctx_val, wildcards):
    assert isinstance(head_pointer_node, TypeVizItemListItemsHeadPointerTypeNode)
    expression = _resolve_wildcards(head_pointer_node.text, wildcards)
    return _eval_expression(ctx_val, expression, None)


@optional_node_processor
def _node_processor_linked_list_items(linked_list_node, ctx_val, wildcards):
    assert isinstance(linked_list_node, TypeVizItemProviderLinkedListItems)
    if linked_list_node.condition:
        condition = _resolve_wildcards(linked_list_node.condition, wildcards)
        if not _process_node_condition(condition, ctx_val):
            return None

    size = _find_first_good_node(linked_list_node.size_nodes,
                                 _node_processor_size,
                                 ctx_val, wildcards)
    # size can be None

    head_pointer_value = _node_processor_linked_list_items_head_pointer(linked_list_node.head_pointer_node, ctx_val,
                                                                        wildcards)

    next_pointer_node = linked_list_node.next_pointer_node
    assert isinstance(next_pointer_node, TypeVizItemListItemsNextPointerTypeNode)
    next_pointer_expression = _resolve_wildcards(next_pointer_node.text, wildcards)

    value_node = linked_list_node.value_node_node
    assert isinstance(value_node, TypeVizItemListItemsIndexNodeTypeNode)
    value_expression = _resolve_wildcards(value_node.expr.text, wildcards)
    value_opts = value_node.expr.view_options

    if value_node.name is None:
        nodes_provider = LinkedListIndexedNodesProvider(size, head_pointer_value, next_pointer_expression)
    else:
        nodes_provider = LinkedListCustomNameNodesProvider(size, head_pointer_value, next_pointer_expression,
                                                           value_node.name, wildcards)

    return CustomItemsProvider(nodes_provider, value_expression, value_opts, wildcards)


def _process_item_provider_linked_list_items(item_provider, val, wildcards):
    return _node_processor_linked_list_items(item_provider, val, wildcards)


class BinaryTreeIndexedNodesProvider(NodesProvider):
    def __init__(self, size, head_pointer, left_expression, right_expression, node_condition):
        super(BinaryTreeIndexedNodesProvider, self).__init__()

        cache = []
        has_more = False

        # iterate all list nodes and cache them
        max_size = size if size is not None else g_max_num_children
        idx = 0
        cur = head_pointer
        stack = []  # parents

        def check_condition(node):
            if node_condition is None:
                return True
            return _check_condition(node.GetNonSyntheticValue().Dereference(), node_condition)

        while (_get_ptr_value(cur) != 0 and check_condition(cur) or stack) and idx < max_size:
            while _get_ptr_value(cur) != 0 and check_condition(cur):
                if len(stack) > 100:  # ~2^100 nodes can't be true - something went wrong
                    raise Exception("Invalid tree")

                stack.append(cur)
                cur = _eval_expression(cur.GetNonSyntheticValue().Dereference(), left_expression, None)

            cur = stack.pop()
            cache.append(cur.GetNonSyntheticValue().Dereference())
            idx += 1

            cur = _eval_expression(cur.GetNonSyntheticValue().Dereference(), right_expression, None)

        if size is None:
            if _get_ptr_value(cur) != 0 and check_condition(cur) or stack and idx >= max_size:
                has_more = True
        else:
            if idx < size:
                cache.extend([None] * (size - idx))

        self.cache = cache
        self.has_more = has_more
        self.names = None
        self.name2index = None


class BinaryTreeCustomNamesNodesProvider(NodesProvider):
    def __init__(self, size, head_pointer, left_expression, right_expression, node_condition, custom_value_name,
                 wildcards):
        super(BinaryTreeCustomNamesNodesProvider, self).__init__()

        cache = []
        has_more = False
        names = []
        name2index = {}

        # iterate all list nodes and cache them
        max_size = size if size is not None else g_max_num_children
        idx = 0
        cur = head_pointer
        stack = []  # parents

        def check_condition(node):
            if node_condition is None:
                return True
            return _check_condition(node.GetNonSyntheticValue().Dereference(), node_condition)

        while (_get_ptr_value(cur) != 0 and check_condition(cur) or stack) and idx < max_size:
            while _get_ptr_value(cur) != 0 and check_condition(cur):
                if len(stack) > 100:  # ~2^100 nodes can't be true - something went wrong
                    raise Exception("Invalid tree")

                stack.append(cur)
                cur = _eval_expression(cur.GetNonSyntheticValue().Dereference(), left_expression, None)

            cur = stack.pop()
            cur_val = cur.GetNonSyntheticValue().Dereference()
            name = _evaluate_interpolated_string(custom_value_name, cur_val, wildcards)
            names.append(name)
            name2index[name] = idx
            cache.append(cur_val)
            idx += 1

            cur = _eval_expression(cur_val, right_expression, None)

        if size is None:
            if _get_ptr_value(cur) != 0 and check_condition(cur) or stack and idx >= max_size:
                has_more = True
        else:
            if idx < size:
                cache.extend([None] * (size - idx))

        self.cache = cache
        self.has_more = has_more
        self.names = names
        self.name2index = name2index


def _node_processor_tree_items_head_pointer(head_pointer_node, ctx_val, wildcards):
    assert isinstance(head_pointer_node, TypeVizItemTreeHeadPointerTypeNode)
    expression = _resolve_wildcards(head_pointer_node.text, wildcards)
    return _eval_expression(ctx_val, expression, None)


@optional_node_processor
def _node_processor_tree_items(tree_node, ctx_val, wildcards):
    assert isinstance(tree_node, TypeVizItemProviderTreeItems)
    if tree_node.condition:
        condition = _resolve_wildcards(tree_node.condition, wildcards)
        if not _process_node_condition(condition, ctx_val):
            return None

    size = _find_first_good_node(tree_node.size_nodes,
                                 _node_processor_size,
                                 ctx_val, wildcards)
    # size can be None

    head_pointer_value = _node_processor_tree_items_head_pointer(tree_node.head_pointer_node, ctx_val,
                                                                 wildcards)

    left_pointer_node = tree_node.left_pointer_node
    right_pointer_node = tree_node.right_pointer_node
    assert isinstance(left_pointer_node, TypeVizItemTreeChildPointerTypeNode)
    assert isinstance(right_pointer_node, TypeVizItemTreeChildPointerTypeNode)
    left_pointer_expression = _resolve_wildcards(left_pointer_node.text, wildcards)
    right_pointer_expression = _resolve_wildcards(right_pointer_node.text, wildcards)

    value_node = tree_node.value_node_node
    assert isinstance(value_node, TypeVizItemTreeNodeTypeNode)
    value_expression = _resolve_wildcards(value_node.expr.text, wildcards)
    value_opts = value_node.expr.view_options

    value_condition = _resolve_wildcards(value_node.condition, wildcards) if value_node.condition else None

    if value_node.name is None:
        nodes_provider = BinaryTreeIndexedNodesProvider(size, head_pointer_value,
                                                        left_pointer_expression, right_pointer_expression,
                                                        value_condition)
    else:
        nodes_provider = BinaryTreeCustomNamesNodesProvider(size, head_pointer_value,
                                                            left_pointer_expression, right_pointer_expression,
                                                            value_condition, value_node.name, wildcards)

    return CustomItemsProvider(nodes_provider, value_expression, value_opts, wildcards)


def _process_item_provider_tree_items(item_provider, val, wildcards):
    return _node_processor_tree_items(item_provider, val, wildcards)


def _build_child_providers(item_providers, valobj_non_synth, wildcards):
    provider_handlers = {
        TypeVizItemProviderTypeKind.Single: _process_item_provider_single,
        TypeVizItemProviderTypeKind.Expanded: _process_item_provider_expanded,
        TypeVizItemProviderTypeKind.ArrayItems: _process_item_provider_array_items,
        TypeVizItemProviderTypeKind.IndexListItems: _process_item_provider_index_list_items,
        TypeVizItemProviderTypeKind.LinkedListItems: _process_item_provider_linked_list_items,
        TypeVizItemProviderTypeKind.TreeItems: _process_item_provider_tree_items,
    }
    child_providers = []
    for item_provider in item_providers:
        handler = provider_handlers.get(item_provider.kind)
        if not handler:
            continue
        child_provider = handler(item_provider, valobj_non_synth, wildcards)
        if not child_provider:
            continue
        child_providers.append(child_provider)

    return child_providers
