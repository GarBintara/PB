from .jb_lldb_logging import log


class DebuggerFormattersState(object):
    def __init__(self):
        self.registered_summaries = set()
        self.registered_synthetics = set()


# Associate source files and storage of parsed type vizualizers.
# Every type viz storage also contains list of registered summaries and synthetics.
class FormattersManager(object):
    class FormatterEntry(object):
        def __init__(self, storage, loader):
            self.storage = storage
            self.loader = loader

    def __init__(self, summary_func_name, synthetic_provider_class_name):
        self.formatter_entries = {}
        self.debugger_formatters_state = {}
        self.summary_func_name = summary_func_name
        self.synthetic_provider_class_name = synthetic_provider_class_name

    def get_all_registered_files(self):
        return self.formatter_entries.keys()

    def get_all_type_viz(self):
        return [e.storage for e in self.formatter_entries.values()]

    def register(self, debugger, filepath, loader):
        log("Registering types storage for '{}'...", filepath)
        self._unregister_lldb(debugger, filepath)
        storage = loader(filepath)
        self.formatter_entries[filepath] = self.FormatterEntry(storage, loader)
        self._register_lldb(debugger, filepath, storage)

    def unregister(self, debugger, filepath):
        self._unregister_lldb(debugger, filepath)

        log("Unregistering types storage for '{}'...", filepath)
        try:
            del self.formatter_entries[filepath]
        except KeyError:
            log("Key '{}' wasn't found in formatters storage...", filepath)
            return

    def reload(self, debugger, filepath):
        try:
            entry = self.formatter_entries[filepath]
        except KeyError:
            log("Key '{}' wasn't found in formatters storage...", filepath)
            return

        self._unregister_lldb(debugger, filepath)

        entry.storage = entry.loader(filepath)
        self._register_lldb(debugger, filepath, entry.storage)

    def unload(self, debugger, filepath):
        self._unregister_lldb(debugger, filepath)

    def _register_lldb(self, debugger, filepath, storage):
        log("Registering formatters from '{}' into {}...", filepath, str(debugger))
        try:
            debugger_state = self.debugger_formatters_state[debugger.GetID()]
        except KeyError:
            debugger_state = {}
            self.debugger_formatters_state[debugger.GetID()] = debugger_state

        try:
            state = debugger_state[filepath]
        except KeyError:
            state = DebuggerFormattersState()
            debugger_state[filepath] = state

        for type_name, type_viz, type_viz_name in storage.iterate_exactly_matched_type_viz():
            debugger.HandleCommand(
                'type summary add "{type_name}" -F {summary} -e --category jb_formatters'
                .format(type_name=type_name, summary=self.summary_func_name))
            state.registered_summaries.add(type_name)
            log("Summary for {type_viz_name} registered as {type_name}",
                type_viz_name=type_viz_name.type_name, type_name=type_name)

            if type_viz.item_providers is not None:
                debugger.HandleCommand(
                    'type synthetic add "{type_name}" -l {synth} --category jb_formatters'
                    .format(type_name=type_name, synth=self.synthetic_provider_class_name))
                state.registered_synthetics.add(type_name)
                log("Synth provider for {type_viz_name} registered as {type_name}",
                    type_viz_name=type_viz_name.type_name, type_name=type_name)

        for type_name_regex, type_viz, type_viz_name in storage.iterate_wildcard_matched_type_viz():
            debugger.HandleCommand(
                'type summary add "{type_name_regex}" -F {summary} -e -x --category jb_formatters'
                .format(type_name_regex=type_name_regex, summary=self.summary_func_name))
            state.registered_summaries.add(type_name_regex)
            log("Summary for {type_name} registered as regex {regex}",
                type_name=type_viz_name.type_name, regex=type_name_regex)

            if type_viz.item_providers is not None:
                debugger.HandleCommand(
                    'type synthetic add "{type_name_regex}" -x -l {synth} --category jb_formatters'
                    .format(type_name_regex=type_name_regex, synth=self.synthetic_provider_class_name))
                state.registered_synthetics.add(type_name_regex)
                log("Synth provider for {type_name} registered as regex {regex}",
                    type_name=type_viz_name.type_name, regex=type_name_regex)

    def _unregister_lldb(self, debugger, filepath):
        log("Unregistering formatters from '{}' from {}...", filepath, str(debugger))
        try:
            debugger_state = self.debugger_formatters_state[debugger.GetID()]
        except KeyError:
            log("No loaded formatters found for {}", str(debugger))
            return

        try:
            state = debugger_state[filepath]
        except KeyError:
            log("No loaded formatters loaded into {} found for {}", str(debugger), filepath)
            return

        for type_name in state.registered_summaries:
            log("Unloading summary for type '{}'", type_name)
            debugger.HandleCommand(
                'type summary delete "{type_name}" --category jb_formatters'
                .format(type_name=type_name))

        for type_name in state.registered_synthetics:
            log("Unloading synth provider for type '{}'", type_name)
            debugger.HandleCommand(
                'type synthetic delete "{type_name}" --category jb_formatters'
                .format(type_name=type_name))

        del debugger_state[filepath]
