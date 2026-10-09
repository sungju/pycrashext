"""
Checks for kernel version parsing and comparison.

Run directly: python3 source/kernel_version_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from kernel_version import (parse_kernel_version, kernel_version_ge,
                            get_rhel_version, is_rhel_kernel, fix_status,
                            normalize_kernel_version, report)


def check_zstream_is_not_collapsed():
    # The whole z-stream of a release shares one leading release number, so
    # dropping the components after it made every build in 553 compare equal
    # and every '>=' test answer True.
    assert parse_kernel_version('4.18.0-553.5.1.el8_10') != \
           parse_kernel_version('4.18.0-553.159.1.el8_10')
    assert not kernel_version_ge('4.18.0-553.146.1.el8_10.x86_64',
                                 '4.18.0-553.159.1.el8_10')
    assert kernel_version_ge('4.18.0-553.159.1.el8_10',
                             '4.18.0-553.146.1.el8_10.x86_64')


def check_zstream_orders_numerically():
    builds = ['4.18.0-553.%d.1.el8_10' % n for n in (5, 9, 10, 40, 100, 159)]
    for lower, higher in zip(builds, builds[1:]):
        assert kernel_version_ge(higher, lower), (lower, higher)
        assert not kernel_version_ge(lower, higher), (lower, higher)


def check_ga_sorts_below_its_zstream():
    assert kernel_version_ge('4.18.0-553.5.1.el8_10', '4.18.0-553.el8')
    assert not kernel_version_ge('4.18.0-553.el8', '4.18.0-553.5.1.el8_10')


def check_higher_components_dominate():
    # release number outranks z-stream
    assert kernel_version_ge('4.18.0-553.1.1.el8_10', '4.18.0-513.99.1.el8_9')
    # rhel major outranks everything below it
    assert kernel_version_ge('5.14.0-70.1.1.el9_0', '4.18.0-553.159.1.el8_10')
    assert kernel_version_ge('4.18.0-553.el8', '3.10.0-1160.el7')


def check_parsed_shape():
    assert parse_kernel_version('5.14.0-427.el9') == (9, 5, 14, 0, (427,))
    assert parse_kernel_version('4.18.0-553.146.1.el8_10.x86_64') == \
           (8, 4, 18, 0, (553, 146, 1))
    # The release is always a tuple.  A bare int for some versions and a tuple
    # for others would raise TypeError the moment the two were compared.
    for ver in ('5.14.0-427.el9', '4.18.0-553.1.el8',
                '4.18.0-553.146.1.el8_10'):
        assert isinstance(parse_kernel_version(ver)[4], tuple), ver


def check_non_rhel_input():
    for ver in ('v6.9-rc1', '6.9.0-rc1', 'garbage', '', None):
        assert parse_kernel_version(ver) is None, ver
        assert not is_rhel_kernel(ver), ver
    assert kernel_version_ge('garbage', 'garbage')
    assert not kernel_version_ge('garbage', '4.18.0-553.el8')
    assert kernel_version_ge('4.18.0-553.el8', 'garbage')


def check_helpers():
    assert get_rhel_version('4.18.0-553.146.1.el8_10') == 8
    assert get_rhel_version('5.14.0-427.el9') == 9
    assert get_rhel_version('garbage') is None
    assert is_rhel_kernel('4.18.0-553.146.1.el8_10')
    assert kernel_version_ge('4.18.0-553.146.1.el8_10',
                             '4.18.0-553.146.1.el8_10')


def check_sorting():
    # get_version_range_for_repo sorts tags with this key to find the newest
    # release below the running kernel.
    tags = ['4.18.0-553.159.1.el8_10', '4.18.0-553.5.1.el8_10',
            '4.18.0-553.el8', '4.18.0-513.24.1.el8_9', '5.14.0-427.el9']
    assert sorted(tags, key=parse_kernel_version) == [
        '4.18.0-513.24.1.el8_9',
        '4.18.0-553.el8',
        '4.18.0-553.5.1.el8_10',
        '4.18.0-553.159.1.el8_10',
        '5.14.0-427.el9',
    ]


def check_fix_status():
    kcs = ['kernel-5.14.0-162.6.1.el9_1', 'kernel-4.18.0-425.3.1.el8',
           'kernel-4.18.0-372.32.1.el8_6', 'kernel-3.10.0-1160.81.1.el7']
    # Same minor release: the only exact answer, z-stream compared in full.
    assert fix_status('4.18.0-372.40.1.el8_6.x86_64', kcs)[:2] == \
           ('FIXED', '4.18.0-372.32.1.el8_6')
    assert fix_status('4.18.0-372.9.1.el8_6', kcs)[:2] == \
           ('NOT_FIXED', '4.18.0-372.32.1.el8_6')
    # Later minor release with no fix listed for it: inferred only.
    assert fix_status('4.18.0-553.77.1.el8_10', kcs)[:2] == \
           ('LIKELY_FIXED', '4.18.0-425.3.1.el8')
    # Earlier than every listed fix of its major.
    assert fix_status('4.18.0-305.49.1.el8_4', kcs)[0] == 'NOT_FIXED'
    # The release number alone must not decide: 553.5.1 < 553.77.1.
    assert fix_status('4.18.0-553.5.1.el8_10', ['4.18.0-553.77.1.el8'])[0] == 'NOT_FIXED'
    assert fix_status('4.18.0-553.77.1.el8_10', ['4.18.0-553.77.1.el8_10'])[0] == 'FIXED'
    assert fix_status('5.14.0-70.13.1.el9_0', ['kernel-4.18.0-425.3.1.el8'])[0] == 'NO_MATCH'
    assert fix_status('garbage', kcs)[0] == 'UNKNOWN'
    assert normalize_kernel_version('kernel-rt-4.18.0-425.3.1.rt7.el8') == '4.18.0-425.3.1.rt7.el8'
    verdict, text = report('4.18.0-553.77.1.el8_10', kcs)
    assert verdict == 'LIKELY_FIXED'
    assert text.splitlines()[-1] == \
        'KVERCMP verdict=LIKELY_FIXED current=4.18.0-553.77.1.el8_10 fix=4.18.0-425.3.1.el8'
    assert 'other RHEL major, not compared' in text


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
