"""
autocheck rule: crash loaded debuginfo of another build for a third-party
module, so its source lines, struct layouts and 'edis -T' are wrong.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import ntpath

import modinfo


def is_major():
    return True


def description():
    return "Checking that third-party modules' debuginfo matches the loaded build"


def add_rule(sysinfo):
    return True


def run_rule(basic_data):
    try:
        modinfo.load_module_details()
        found = []
        for module in modinfo.module_list:
            signed = bool(module.sig_ok) if modinfo._has_member("sig_ok") else None
            if not modinfo.is_third_party(modinfo.module_taints(module), signed):
                continue
            if modinfo.debuginfo_status(module) == "mismatch":
                found.append(module)
        if not found:
            return None

        lines = []
        for module in found:
            for warn, text in modinfo.debuginfo_note(module):
                lines.append("%s: %s" % (module.name, text.replace("\n", " ")))
        result_dict = {}
        result_dict["TITLE"] = "debuginfo of another build loaded for %s, detected by %s" % (
            ", ".join(str(m.name) for m in found), ntpath.basename(__file__))
        result_dict["MSG"] = "\n".join(lines)
        result_dict["KCS_TITLE"] = "No KCS: crash picks module debuginfo by name, and an" \
                                   " out-of-tree module can share an in-tree module's name"
        result_dict["RESOLUTION"] = "Do not trust source lines, structs or 'edis -T' for" \
                                    " these modules. Get the vendor's matching .ko or" \
                                    " .ko.debug and load it with 'mod -s <module> <file>'."
        result_dict["KERNELS"] = ["Not a kernel issue"]
        return [result_dict]
    except Exception as e:
        print(e)
        return None


if (__name__ == '__main__'):
    import pprint
    pprint.PrettyPrinter(indent=0, width=180).pprint(run_rule(None))
