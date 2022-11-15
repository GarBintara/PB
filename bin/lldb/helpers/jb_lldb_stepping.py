import lldb

FIND_NEAREST_INSTRUCTION_STEP = 16


def get_full_step_name(step_name):
    return __name__ + '.' + step_name


def is_process_x64(process):
    return process.GetAddressByteSize() == 8


def get_line_entry(frame):
    if frame is None:
        return None

    line_entry = frame.GetLineEntry()
    if line_entry.IsValid() and line_entry.GetFileSpec().Exists():
        return line_entry

    return None


def get_nearest_line_frame(thread):
    for i in range(0, thread.GetNumFrames()):
        frame = thread.GetFrameAtIndex(i)
        if get_line_entry(frame):
            return frame

    return None


class InstructionsHelper(object):
    def __init__(self, target):
        self.target = target

    def is_call(self, instruction):
        if instruction is None:
            return False

        return instruction.GetMnemonic(self.target).startswith('call')

    def read_instruction(self, address):
        return next(iter(self.target.ReadInstructions(address, 1, 'intel')), None)

    def read_line_entry_instructions(self, line_entry):
        if line_entry is None or not line_entry.IsValid():
            return None

        begin = line_entry.GetStartAddress()
        end = line_entry.GetEndAddress()
        size = end.GetLoadAddress(self.target) - begin.GetLoadAddress(self.target)

        error = lldb.SBError()
        buf = self.target.ReadMemory(begin, size, error)
        if not error.Success():
            return None

        return self.target.GetInstructions(begin, buf)

    def find_nearest_instruction(self, address, cond):
        instructions = self.target.ReadInstructions(address, FIND_NEAREST_INSTRUCTION_STEP)
        while instructions:
            found = next((i for i in instructions if cond(i)), None)
            if found is not None:
                return found

            last = instructions[len(instructions) - 1]
            address = last.GetAddress()
            address.OffsetAddress(last.GetByteSize())

            instructions = self.target.ReadInstructions(address, FIND_NEAREST_INSTRUCTION_STEP)

        return None


class DelegateStep(object):
    def __init__(self, thread_plan, composite):
        self.thread_plan = thread_plan
        self.composite = composite
        self.step_thread_plan = self.queue_thread_plan()

    # noinspection PyUnusedLocal
    def explains_stop(self, event):
        return self.step_thread_plan is None

    # noinspection PyUnusedLocal
    def should_stop(self, event):
        if self.step_thread_plan is not None:
            if not self.step_thread_plan.IsPlanComplete():
                return False

            if self.composite:
                self.step_thread_plan = self.queue_thread_plan()
                if self.step_thread_plan is not None:
                    return False

        self.thread_plan.SetPlanComplete(True)
        return True

    def should_step(self):
        return self.step_thread_plan is None

    def queue_thread_plan(self):
        return None


class StepThroughInstruction(object):
    # noinspection PyUnusedLocal
    def __init__(self, thread_plan, d):
        self.thread_plan = thread_plan
        self.start_pc = self.thread_plan.GetThread().GetFrameAtIndex(0).GetPC()

    # noinspection PyUnusedLocal
    def explains_stop(self, event):
        return self.thread_plan.GetThread().GetStopReason() == lldb.eStopReasonTrace

    # noinspection PyUnusedLocal
    def should_stop(self, event):
        if self.thread_plan.GetThread().GetFrameAtIndex(0).GetPC() == self.start_pc:
            return False

        self.thread_plan.SetPlanComplete(True)
        return True

    # noinspection PyMethodMayBeStatic
    def should_step(self):
        return True


class StepOverInstruction(DelegateStep):
    # noinspection PyUnusedLocal
    def __init__(self, thread_plan, d):
        thread = thread_plan.GetThread()
        self.helper = InstructionsHelper(thread.GetProcess().GetTarget())

        frame = thread.GetFrameAtIndex(0)
        self.start_pc_address = frame.GetPCAddress()

        self.run_to_address = None
        self.sp_limit = None
        self.cfa = None
        instruction = self.helper.read_instruction(self.start_pc_address)
        if self.helper.is_call(instruction):
            self.run_to_address = self.start_pc_address
            self.run_to_address.OffsetAddress(instruction.GetByteSize())
            self.sp_limit = frame.GetSP()
            self.cfa = frame.GetCFA()

        DelegateStep.__init__(self, thread_plan, True)

    def queue_thread_plan(self):
        frame = self.thread_plan.GetThread().GetFrameAtIndex(0)
        address = frame.GetPCAddress()

        if self.run_to_address is not None:
            if address == self.run_to_address:
                if frame.GetSP() >= self.sp_limit or frame.GetCFA() == self.cfa:
                    return None

                return self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('StepThroughInstruction'))

            return self.thread_plan.QueueThreadPlanForRunToAddress(self.run_to_address)

        if address != self.start_pc_address:
            return None

        return self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('StepThroughInstruction'))


class StepLine(DelegateStep):
    def __init__(self, thread_plan, step_over, force):
        thread = thread_plan.GetThread()
        self.helper = InstructionsHelper(thread.GetProcess().GetTarget())

        self.step_over = step_over
        self.force = force

        frame = thread.GetFrameAtIndex(0)
        start_line_entry = get_line_entry(frame)
        self.start_line = start_line_entry.GetLine() if start_line_entry is not None else None
        self.sp_limit = frame.GetSP()

        DelegateStep.__init__(self, thread_plan, True)

    def queue_thread_plan(self):
        thread = self.thread_plan.GetThread()
        frame = thread.GetFrameAtIndex(0)
        line_entry = get_line_entry(frame)
        line = line_entry.GetLine() if line_entry is not None else None

        sp = frame.GetSP()
        if line is None:
            if self.force:
                return None

            if sp > self.sp_limit and get_nearest_line_frame(thread) is None:
                return None

            skip_plan = self.get_skip_instructions_plan(thread)
            if skip_plan is not None:
                return skip_plan

            return self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('StepOverInstruction'))

        if line != self.start_line:
            return None

        if sp > self.sp_limit:
            self.sp_limit = sp

        skip_plan = self.get_skip_instructions_plan(thread)
        if skip_plan is not None:
            return skip_plan

        return self.thread_plan.QueueThreadPlanForStepScripted(
            get_full_step_name('StepOverInstruction' if self.step_over else 'StepThroughInstruction'))

    def get_skip_instructions_plan(self, thread):
        frame = thread.GetFrameAtIndex(0)
        line_entry = get_line_entry(frame)
        line = line_entry.GetLine() if line_entry is not None else None
        if line is None and frame.GetSP() > self.sp_limit:
            nearest_line_frame = get_nearest_line_frame(thread)
            if nearest_line_frame is not None:
                return self.thread_plan.QueueThreadPlanForRunToAddress(nearest_line_frame.GetPCAddress())

        def is_interesting_instruction(i):
            le = get_line_entry(i.GetAddress())
            ln = le.GetLine() if le is not None else None
            if ln != line:
                return True

            if i.DoesBranch():
                return True

            return False

        curr_pc = frame.GetPCAddress()
        next_instruction = self.helper.find_nearest_instruction(curr_pc, is_interesting_instruction)
        if next_instruction is None:
            return None

        next_address = next_instruction.GetAddress()
        if next_address == curr_pc:
            return None

        return self.thread_plan.QueueThreadPlanForRunToAddress(next_address)


class StepInLine(StepLine):
    # noinspection PyUnusedLocal
    def __init__(self, thread_plan, d):
        StepLine.__init__(self, thread_plan, False, False)


class StepInLineForce(StepLine):
    # noinspection PyUnusedLocal
    def __init__(self, thread_plan, d):
        StepLine.__init__(self, thread_plan, False, True)


class StepOverLine(StepLine):
    # noinspection PyUnusedLocal
    def __init__(self, thread_plan, d):
        StepLine.__init__(self, thread_plan, True, False)


class StepOverLineForce(StepLine):
    # noinspection PyUnusedLocal
    def __init__(self, thread_plan, d):
        StepLine.__init__(self, thread_plan, True, True)


class SpecialLinesGuardThreadPlan(object):
    ASI = 0xfeefee
    NSI = 0xf00f00

    # noinspection PyUnusedLocal
    def __init__(self, thread_plan, d):
        self.thread_plan = thread_plan

    # noinspection PyMethodMayBeStatic,PyUnusedLocal
    def explains_stop(self, event):
        return False

    # noinspection PyUnusedLocal
    def should_stop(self, event):
        thread = self.thread_plan.GetThread()
        frame = thread.GetFrameAtIndex(0)
        line_entry = get_line_entry(frame)
        line = line_entry.GetLine() if line_entry is not None else None

        if line == self.ASI:
            self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('StepInLine'))
            return False

        if line == self.NSI:
            self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('StepOverLine'))
            return False

        self.thread_plan.SetPlanComplete(True)
        return True

    # noinspection PyMethodMayBeStatic
    def should_step(self):
        return False


class NonLocalGotoReturnGuardThreadPlan(object):
    # noinspection PyUnusedLocal
    def __init__(self, thread_plan, d):
        self.thread_plan = thread_plan

        self.addresses = []
        target = self.thread_plan.GetThread().GetProcess().GetTarget()
        for sym_ctx in target.FindSymbols(self.get_nlg_return_symbol_name()):
            bp_address = sym_ctx.GetSymbol().GetStartAddress().GetLoadAddress(target)
            if bp_address == lldb.LLDB_INVALID_ADDRESS:
                continue
            self.addresses.append(bp_address)

    # noinspection PyMethodMayBeStatic,PyUnusedLocal
    def explains_stop(self, event):
        return False

    # noinspection PyUnusedLocal
    def should_stop(self, event):
        if self.thread_plan.GetThread().GetFrameAtIndex(0).GetPC() in self.addresses:
            return False

        self.thread_plan.SetPlanComplete(True)
        return True

    # noinspection PyMethodMayBeStatic
    def should_step(self):
        return False

    @staticmethod
    def get_nlg_return_symbol_name():
        return '_NLG_Return'


class NonLocalGotoDispatchGuardThreadPlan(object):
    # noinspection PyUnusedLocal
    def __init__(self, thread_plan, d):
        self.thread_plan = thread_plan

        thread = self.thread_plan.GetThread()
        process = thread.GetProcess()
        self.is_x64 = is_process_x64(process)

        self.sp_limit = thread.GetFrameAtIndex(0).GetSP()

        self.bp_addresses = []
        self.bp_ids = []
        target = process.GetTarget()
        for sym_ctx in target.FindSymbols(self.get_nlg_dispatch_symbol_name(self.is_x64)):
            bp_address = sym_ctx.GetSymbol().GetStartAddress().GetLoadAddress(target)
            if bp_address == lldb.LLDB_INVALID_ADDRESS:
                continue
            self.bp_addresses.append(bp_address)

            bp = target.BreakpointCreateByAddress(bp_address)
            bp.SetThreadID(thread.GetThreadID())
            self.bp_ids.append(bp.GetID())

    # noinspection PyUnusedLocal
    def explains_stop(self, event):
        return self.thread_plan.GetThread().GetFrameAtIndex(0).GetPC() in self.bp_addresses

    # noinspection PyUnusedLocal
    def should_stop(self, event):
        thread = self.thread_plan.GetThread()
        frame = thread.GetFrameAtIndex(0)
        if frame.GetPC() not in self.bp_addresses:
            self.thread_plan.SetPlanComplete(True)
            return True

        nlg_frame_register = frame.FindRegister(self.get_nlg_frame_register_name(self.is_x64))
        if not nlg_frame_register:
            return False

        if nlg_frame_register.GetValueAsUnsigned() < self.sp_limit:
            return False

        nlg_address_register = frame.FindRegister(self.get_nlg_address_register_name(self.is_x64))
        if not nlg_address_register:
            return False

        nlg_address = thread.GetProcess().GetTarget().ResolveLoadAddress(nlg_address_register.GetValueAsUnsigned())
        if not nlg_address:
            return False

        if get_line_entry(nlg_address) is None:
            return False

        self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('NonLocalGotoDispatchGuardThreadPlan'),
                                                        lldb.SBError(),
                                                        True)
        self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('NonLocalGotoReturnGuardThreadPlan'))
        self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('SpecialLinesGuardThreadPlan'))
        self.thread_plan.QueueThreadPlanForRunToAddress(nlg_address)

        return False

    # noinspection PyMethodMayBeStatic
    def should_step(self):
        return False

    def will_pop(self):
        target = self.thread_plan.GetThread().GetProcess().GetTarget()
        for bp_id in self.bp_ids:
            target.BreakpointDelete(bp_id)

        return True

    @staticmethod
    def get_nlg_dispatch_symbol_name(is_x64):
        return '__NLG_Dispatch2' if is_x64 else '_NLG_Dispatch2'

    @staticmethod
    def get_nlg_frame_register_name(is_x64):
        return 'rdx' if is_x64 else 'ebp'

    @staticmethod
    def get_nlg_address_register_name(is_x64):
        return 'rcx' if is_x64 else 'eax'


class StepIn(DelegateStep):
    # noinspection PyUnusedLocal
    def __init__(self, thread_plan, d):
        DelegateStep.__init__(self, thread_plan, False)

    def queue_thread_plan(self):
        self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('NonLocalGotoDispatchGuardThreadPlan'))
        self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('NonLocalGotoReturnGuardThreadPlan'))

        thread = self.thread_plan.GetThread()
        if get_line_entry(thread.GetFrameAtIndex(0)) is None:
            return self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('StepThroughInstruction'))

        debugger = thread.GetProcess().GetTarget().GetDebugger()
        avoid_no_debug = debugger.GetInternalVariableValue('target.process.thread.step-in-avoid-nodebug',
                                                           debugger.GetInstanceName()).GetStringAtIndex(0)
        if avoid_no_debug == 'false':
            return self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('StepInLineForce'))

        self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('SpecialLinesGuardThreadPlan'))
        return self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('StepInLine'))


class StepOver(DelegateStep):
    # noinspection PyUnusedLocal
    def __init__(self, thread_plan, d):
        DelegateStep.__init__(self, thread_plan, False)

    def queue_thread_plan(self):
        self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('NonLocalGotoDispatchGuardThreadPlan'))
        self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('NonLocalGotoReturnGuardThreadPlan'))

        if get_line_entry(self.thread_plan.GetThread().GetFrameAtIndex(0)) is None:
            return self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('StepOverInstruction'))

        self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('SpecialLinesGuardThreadPlan'))
        return self.thread_plan.QueueThreadPlanForStepScripted(get_full_step_name('StepOverLine'))
