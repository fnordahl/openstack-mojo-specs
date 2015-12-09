#!/usr/bin/python
import argparse
import sys
import utils.mojo_utils as mojo_utils
import logging
from collections import OrderedDict

OPENSTACK_CODENAMES = OrderedDict([
    ('2011.2', 'diablo'),
    ('2012.1', 'essex'),
    ('2012.2', 'folsom'),
    ('2013.1', 'grizzly'),
    ('2013.2', 'havana'),
    ('2014.1', 'icehouse'),
    ('2014.2', 'juno'),
    ('2015.1', 'kilo'),
    ('2015.2', 'liberty'),
])

CHARM_TYPES = {
    'neutron': {
        'pkg': 'neutron-common',
        'origin_setting': 'openstack-origin'
    },
    'nova': {
        'pkg': 'nova-common',
        'origin_setting': 'openstack-origin'
    },
    'glance': {
        'pkg': 'glance-common',
        'origin_setting': 'openstack-origin'
    },
    'cinder': {
        'pkg': 'cinder-common',
        'origin_setting': 'openstack-origin'
    },
    'keystone': {
        'pkg': 'keystone',
        'origin_setting': 'openstack-origin'
    },
    'openstack-dashboard': {
        'pkg': 'openstack-dashboard',
        'origin_setting': 'openstack-origin'
    },
    'ceilometer': {
        'pkg': 'ceilometer-common',
        'origin_setting': 'openstack-origin'
    },
}
UPGRADE_SERVICES = [
    {'name': 'keystone', 'type': CHARM_TYPES['keystone']},
    {'name': 'nova-cloud-controller', 'type': CHARM_TYPES['nova']},
    {'name': 'nova-compute', 'type': CHARM_TYPES['nova']},
    {'name': 'neutron-api', 'type': CHARM_TYPES['neutron']},
    {'name': 'neutron-gateway', 'type': CHARM_TYPES['neutron']},
    {'name': 'glance', 'type': CHARM_TYPES['glance']},
    {'name': 'cinder', 'type': CHARM_TYPES['cinder']},
    {'name': 'openstack-dashboard',
     'type': CHARM_TYPES['openstack-dashboard']},
    {'name': 'ceilometer', 'type': CHARM_TYPES['ceilometer']},
]


def get_os_code_info(pkg_version):
    for entry in OPENSTACK_CODENAMES:
        if entry in pkg_version:
            return {'code_num': entry, 'code_name': OPENSTACK_CODENAMES[entry]}


def next_release(release):
    old_index = OPENSTACK_CODENAMES.keys().index(release)
    new_index = old_index + 1
    return OPENSTACK_CODENAMES.items()[new_index]


def get_current_os_versions(deployed_services):
    versions = {}
    for service in UPGRADE_SERVICES:
        if service['name'] not in deployed_services:
            continue
        version = mojo_utils.get_pkg_version(service['name'],
                                             service['type']['pkg'])
        versions[service['name']] = get_os_code_info(version)
    return versions


def get_lowest_os_version(current_versions):
    lowest_version = {'code_num': '2100', 'code_name': 'zebra'}
    for svc in current_versions.keys():
        if current_versions[svc]['code_name'] < lowest_version['code_name']:
            lowest_version = current_versions[svc]
    return lowest_version


def get_upgrade_targets(target_release, current_versions):
    upgrade_list = []
    for svc in current_versions.keys():
        if current_versions[svc]['code_name'] < target_release:
            upgrade_list.append(svc)
    return upgrade_list


def main(argv):
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--target_release",
        default='auto', help="Openstack release name to upgrade to or 'auto' "
                             "to have script upgrade based on the lowest value"
                             "across all services")
    options = parser.parse_args()
    target_release = mojo_utils.parse_mojo_arg(options, 'target_release')
    principle_services = mojo_utils.get_principle_services()
    current_versions = get_current_os_versions(principle_services)
    if target_release == 'auto':
        # If in auto mode find the lowest value openstack release across all
        # services and make sure all servcies are upgraded to one release
        # higher than the lowest
        lowest_release = get_lowest_os_version(current_versions)['code_num']
        target_release = next_release(lowest_release)[1]
    # Get a list of services that need upgrading
    needs_upgrade = get_upgrade_targets(target_release, current_versions)
    for service in UPGRADE_SERVICES:
        if service['name'] not in principle_services:
            continue
        if service['name'] not in needs_upgrade:
            logging.info('Not upgrading {} it is at {} or higher'.format(
                service['name'],
                target_release)
            )
            continue
        logging.info('Upgrading {} to {}'.format(service['name'],
                                                 target_release))
        ubuntu_version = mojo_utils.get_ubuntu_version(service['name'])
        option = "{}=cloud:{}-{}".format(service['type']['origin_setting'],
                                         ubuntu_version, target_release)
        mojo_utils.juju_set(service['name'], option, wait=True)

if __name__ == "__main__":
    sys.exit(main(sys.argv))