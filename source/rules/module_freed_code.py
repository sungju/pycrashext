"""
autocheck rule: a task runs, or returns into, freed memory in the module
area: code of an unloaded module or of a freed BPF program or trampoline.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import ntpath

import modinfo


def is_major():
    return True


def description():
    return "Checking for frames in freed module-area memory (unloaded module, freed BPF)"


def add_rule(sysinfo):
    return True


def run_rule(basic_data):
    try:
        frames = modinfo.parse_backtraces("PID:".join(basic_data["bt_a"]))
        ranges = modinfo.code_ranges()
        areas = modinfo.module_areas()
        freed = dict(modinfo.frames_by_module(frames, ranges, areas)).get(modinfo.UNLOADED)
        if not freed:
            return None

        lines = ["PID %d (%s) CPU %d %s %s at 0x%x" % (pid, comm, cpu, frame, func, addr)
                 for pid, comm, cpu, frame, func, addr in freed[:10]]
        addrs = sorted(set(f[5] for f in freed))
        mapped = ["0x%x: %s" % (a, "still mapped" if modinfo.vmap_area(a) else "not mapped (freed)")
                  for a in addrs[:8]]
        last = modinfo.last_unloaded_module_str()
        if last:
            origin = "The last unloaded module was %s: check whether it left a timer," \
                     " work, callback or thread behind." % last
        else:
            origin = "No module has been unloaded since boot, so this is most likely" \
                     " a BPF program or trampoline that was freed while still in use."

        result_dict = {}
        result_dict["TITLE"] = "%d frame%s in freed module-area memory, detected by %s" % (
            len(freed), "" if len(freed) == 1 else "s", ntpath.basename(__file__))
        result_dict["MSG"] = "\n".join(lines + [""] + mapped + ["", origin,
                             "'modinfo -b' and 'modinfo --hooks all' show more."])
        result_dict["KCS_TITLE"] = "No KCS: code in the module area that no loaded module," \
                                   " BPF program or trampoline owns"
        result_dict["RESOLUTION"] = "Find what freed this code while it was still in use:" \
                                    " the unloaded module, or the BPF program's loader" \
                                    " (security and monitoring agents load many)."
        result_dict["KERNELS"] = ["Depends on what freed the code"]
        return [result_dict]
    except Exception as e:
        print(e)
        return None


if (__name__ == '__main__'):
    import pprint
    pprint.PrettyPrinter(indent=0, width=180).pprint(run_rule(None))
