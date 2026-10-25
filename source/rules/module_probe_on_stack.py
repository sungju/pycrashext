"""
autocheck rule: the crashing task was in a kernel function a third-party
module probes (kprobe, kretprobe), or in a probe trampoline: the module's
code runs there even when none of its own frames are on the stack.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import ntpath

import modinfo
import rules_helper as rh


def is_major():
    return True


def description():
    return "Checking whether the crashing task was in a function a third-party module probes"


def add_rule(sysinfo):
    return True


def third_party_names():
    modinfo.load_module_details()
    names = set()
    for module in modinfo.module_list:
        signed = bool(module.sig_ok) if modinfo._has_member("sig_ok") else None
        if modinfo.is_third_party(modinfo.module_taints(module), signed):
            names.add(str(module.name))
    return names


def run_rule(basic_data):
    try:
        third = third_party_names()
        if not third:
            return None
        ranges = modinfo.code_ranges()
        areas = modinfo.module_areas()
        probes = modinfo.module_probes(ranges, areas)
        probes = dict((func, [p for p in plist if p[2] in third or p[2] == modinfo.UNLOADED])
                      for func, plist in probes.items())
        probes = dict((func, plist) for func, plist in probes.items() if plist)
        if not probes:
            return None
        # The crashing task only: agents probe hot paths every task goes
        # through, so another task in them says little.
        frames = modinfo.parse_backtraces(rh.get_data(basic_data, "bt"))
        hooked, trampolines = modinfo.hooked_frames(frames, probes)
        if not hooked and not trampolines:
            return None

        lines = []
        for frame, plist in hooked:
            owners = ", ".join(sorted(set("%s %s of %s" % (k, f, o) for k, f, o, h in plist)))
            lines.append("%s %s: %s" % (frame[3], frame[4], owners))
        for frame, owners in trampolines:
            lines.append("%s %s: %s" % (frame[3], frame[4],
                                        "kretprobes of %s" % ", ".join(owners) if owners
                                        else "probe or ftrace trampoline"))
        modules = sorted(set(p[2] for _, plist in hooked for p in plist) |
                         set(o for _, owners in trampolines for o in owners))
        result_dict = {}
        result_dict["TITLE"] = "crashing task in functions probed by %s, detected by %s" % (
            ", ".join(modules) or "a module", ntpath.basename(__file__))
        result_dict["MSG"] = "PID %d (%s):\n" % (frames[0][0], frames[0][1]) + \
            "\n".join(lines) + "\n\n'modinfo --hooks <module>' lists every probe it installed."
        result_dict["KCS_TITLE"] = "Red Hat support for third-party kernel modules"
        result_dict["KCS_URL"] = "https://access.redhat.com/third-party-software-support"
        result_dict["RESOLUTION"] = "The probe handlers run inside these functions: involve" \
                                    " the module's vendor, and check whether the crash" \
                                    " reproduces with the module unloaded."
        result_dict["KERNELS"] = ["Depends on the module"]
        return [result_dict]
    except Exception as e:
        print(e)
        return None


if (__name__ == '__main__'):
    import pprint
    pprint.PrettyPrinter(indent=0, width=180).pprint(run_rule(None))
