class TypeNameTemplate(object):
    def __init__(self, name, fmt=None, args=None):
        super(TypeNameTemplate, self).__init__()

        if args is None:
            args = []

        self.name = name
        self.fmt = fmt
        self.args = args

    def __str__(self):
        if self.args:
            return self.fmt.format(*map(str, self.args))

        return self.name

    @property
    def has_wildcard(self):
        if self.is_wildcard:
            return True

        for arg in self.args:
            if arg.has_wildcard:
                return True

        return False

    @property
    def is_wildcard(self):
        return self.name == '*'

    def match(self, candidate, out_matched_args=None, logger=None):
        if self.is_wildcard:
            if out_matched_args is not None:
                out_matched_args.append(candidate)
            return True

        if self.name != candidate.name:
            return False

        args_count = len(self.args)
        candidate_args_count = len(candidate.args)
        if args_count > candidate_args_count:
            return False

        for l, r in zip(self.args, candidate.args[:args_count]):
            if not l.match(r, out_matched_args, logger):
                return False

        # Handle special case:
        # trying to match type
        #   T<..., A, B, ...>
        # to template type
        #   T<..., *>
        # We need to properly match A, B, ... types as out_matched args for single wildcard
        if args_count < candidate_args_count:
            # if last template arg is not wildcard
            if args_count == 0 or not self.args[-1].is_wildcard:
                return False
            if out_matched_args is not None:
                out_matched_args.extend(candidate.args[args_count:])

        return True
