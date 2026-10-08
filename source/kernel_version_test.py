"""
Checks for kernel version parsing and comparison.

Run directly: python3 source/kernel_version_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from kernel_version import (parse_kernel_version, kernel_version_ge,
                            get_rhel_version, is_rhel_kernel)


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


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
