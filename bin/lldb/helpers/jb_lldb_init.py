import lldb

# Initialize steps
lldb.debugger.HandleCommand('command script import jb_lldb_stepping')

# And then enable our formatters
lldb.debugger.CreateCategory('jb_formatters').SetEnabled(True)
