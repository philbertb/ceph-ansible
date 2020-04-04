#!/usr/bin/python3
# Copyright 2018, Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: ceph_pool

author: Guillaume Abrioux <gabrioux@redhat.com>

short_description: Manage Ceph Pools

version_added: "2.8"

description:
    - Manage Ceph pool(s) creation, deletion and updates.
options:
    cluster:
        description:
            - The ceph cluster name.
        required: false
        default: ceph
    name:
        description:
            - name of the Ceph pool
        required: true
    state:
        description:
            If 'present' is used, the module creates a pool if it doesn't exist or
            update it if it already exists.
            If 'absent' is used, the module will simply delete the pool.
            If 'list' is used, the module will return all details about the existing pools
            (json formatted).
        required: true
        choices: ['present', 'absent', 'list']
        default: list
    size:
        description:
            - set the replica size of the pool.
        required: false
        default: 3
'''

EXAMPLES = '''

put example here
'''

RETURN = '''#  '''

from ansible.module_utils.basic import AnsibleModule  # noqa E402
import datetime  # noqa E402
import grp  # noqa E402
import json  # noqa E402
import os  # noqa E402
import pwd  # noqa E402
import stat  # noqa E402
import struct  # noqa E402
import time  # noqa E402
import base64  # noqa E402
import socket  # noqa E402


def str_to_bool(val):
    try:
        val = val.lower()
    except AttributeError:
        val = str(val).lower()
    if val == 'true':
        return True
    elif val == 'false':
        return False
    else:
        raise ValueError("Invalid input value: %s" % val)

def fatal(message, module):
    '''
    Report a fatal error and exit
    '''

    if module:
        module.fail_json(msg=message, rc=1)
    else:
        raise(Exception(message))


def container_exec(binary, container_image):
    '''
    Build the docker CLI to run a command inside a container
    '''

    container_binary = os.getenv('CEPH_CONTAINER_BINARY')
    command_exec = [container_binary,
                    'run',
                    '--rm',
                    '--net=host',
                    '-v', '/etc/ceph:/etc/ceph:z',
                    '-v', '/var/lib/ceph/:/var/lib/ceph/:z',
                    '-v', '/var/log/ceph/:/var/log/ceph/:z',
                    '--entrypoint=' + binary, container_image]
    return command_exec


def is_containerized():
    '''
    Check if we are running on a containerized cluster
    '''

    if 'CEPH_CONTAINER_IMAGE' in os.environ:
        container_image = os.getenv('CEPH_CONTAINER_IMAGE')
    else:
        container_image = None

    return container_image


def generate_ceph_cmd(cluster, args, user, user_key, container_image=None):
    '''
    Generate 'ceph' command line to execute
    '''

    if container_image:
        binary = 'ceph'
        cmd = container_exec(
            binary, container_image)
    else:
        binary = ['ceph']
        cmd = binary

    base_cmd = [
        '-n',
        user,
        '-k',
        user_key,
        '--cluster',
        cluster,
        'osd',
        'pool'
    ]

    cmd.extend(base_cmd + args)

    return cmd


def exec_commands(module, cmd_list):
    '''
    Execute command(s)
    '''

    for cmd in cmd_list:
        rc, out, err = module.run_command(cmd)
        if rc != 0:
            return rc, cmd, out, err

    return rc, cmd, out, err

def check_pool_exist(module, cluster, name, user, user_key, output_format='json', container_image=None):
    '''
    Check if a given pool exists
    '''

    cmd_list = []

    args = [ 'stats', name, '-f', output_format ]

    cmd_list.append(generate_ceph_cmd(cluster=cluster, args=args, user=user, user_key=user_key, container_image=container_image))

    rc, cmd, out, err = exec_commands(module, cmd_list)

    return rc, cmd, out, err


def get_pool_details(module, cluster, name, user, user_key, output_format='json', container_image=None):
    '''
    Get details about a given pool
    '''

    cmd_list = []

    args = [ 'ls', 'detail', '-f', output_format ]

    cmd_list.append(generate_ceph_cmd(cluster=cluster, args=args, user=user, user_key=user_key, container_image=container_image))

    rc, cmd, out, err = exec_commands(module, cmd_list)

    if rc == 0:
        out = [p for p in json.loads(out.strip()) if p['pool_name'] == name][0]

    return rc, cmd, out, err


def compare_pool_config(user_pool_config, running_pool_details):
    '''
    Compare user input config pool details with current running pool details
    '''
    
    delta = {}
    filter_keys = [ 'pg_num', 'pg_placement_num', 'size', 'pg_autoscale_mode']
    for key in filter_keys:
        if str(running_pool_details[key]) != user_pool_config[key]['value']:
            delta[key] = user_pool_config[key]

    return delta


def list_pools(cluster, name, user, user_key, details, output_format='json', container_image=None):
    '''
    List existing pools
    '''

    cmd_list = []

    args = [ 'ls' ]

    if details:
        args.append('detail')

    args.extend([ '-f', output_format ])

    cmd_list.append(generate_ceph_cmd(cluster=cluster, args=args, user=user, user_key=user_key, container_image=container_image))

    return cmd_list


def create_pool(cluster, name, user, user_key, user_pool_config, container_image=None):
    '''
    Create a new pool
    '''

    cmd_list = []

    args = [ 'create', user_pool_config['pool_name'], user_pool_config['pg_num'], user_pool_config['pg_placement_num'], user_pool_config['type'] ]

    if pool_type == 'replicated':
        args.extend([ rule_name, user_pool_config['expected_num_objects'] ])

    cmd_list.append(generate_ceph_cmd(cluster=cluster, args=args, user=user, user_key=user_key, container_image=container_image))

    return cmd_list


def update_pool(module, cluster, name, user, user_key, delta, container_image=None):
    '''
    Update an existing pool
    '''

    report = ""

    for key in delta.keys():
        cmd_list = []

        args = [ 'set', name, delta[key]['cli_set_opt'], delta[key]['value'] ]

        cmd_list.append(generate_ceph_cmd(cluster=cluster, args=args, user=user, user_key=user_key, container_image=container_image))

        rc, cmd, out, err = exec_commands(module, cmd_list)

        if rc == 0:
            report = report + "\n" + "{} has been updated: {} is now {}".format(name, key, delta[key]['value'])
        else:
            return rc, cmd, out, err

    out = report
    return rc, cmd, out, err


def exit_module(module, out, rc, cmd, err, startd, changed=False):
    endd = datetime.datetime.now()
    delta = endd - startd

    result = dict(
        cmd=cmd,
        start=str(startd),
        end=str(endd),
        delta=str(delta),
        rc=rc,
        stdout=out.rstrip("\r\n"),
        stderr=err.rstrip("\r\n"),
        changed=changed,
    )
    module.exit_json(**result)

def run_module():
    module_args = dict(
        cluster=dict(type='str', required=False, default='ceph'),
        name=dict(type='str', required=False),
        state=dict(type='str', required=True),
        details=dict(type='bool', required=False, default=False),
        size=dict(type='str', required=False, default="3"),
        pg=dict(type='str', required=False, default="16"),
        pgp=dict(type='str', required=False, default="16"),
        pg_autoscale_mode=dict(type='str', required=False, default='on'),
        pool_type=dict(type='str', required=False, default='replicated'),
        erasure_profile=dict(type='str', required=False, default='erasure-default'),
        rule_name=dict(type='str', required=False, default='replicated_rule'),
        expected_num_objects=dict(type='str', required=False, default="0"),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        add_file_common_args=True,
    )

    file_args = module.load_file_common_arguments(module.params)


    # Gather module parameters in variables
    cluster = module.params.get('cluster')
    name = module.params.get('name')
    state = module.params.get('state')
    details = module.params.get('details')
    pg = module.params.get('pg')
    pgp = module.params.get('pgp')
    pg_autoscale_mode = module.params.get('pg_autoscale_mode')
    pool_type = module.params.get('pool_type')
    size = module.params.get('size')
    erasure_profile = module.params.get('erasure_profile')
    rule_name = module.params.get('rule_name')
    expected_num_objects = module.params.get('expected_num_objects')



    user_pool_config = {
        'pool_name': { 'value': name },
        'size': { 'value': size, 'cli_set_opt': 'size' },
        'pg_num': { 'value': pg, 'cli_set_opt': 'pg_num' },
        'pg_placement_num': { 'value': pgp, 'cli_set_opt': 'pgp_num' },
        'pg_autoscale_mode': { 'value': pg_autoscale_mode, 'cli_set_opt': 'pg_autoscale_mode' },
        'type': { 'value': pool_type },
        'erasure_code_profile': { 'value': erasure_profile },
        'crush_rule': { 'value': rule_name, 'cli_set_opt': 'crush_rule' },
        'expected_num_objects': { 'value': expected_num_objects }
    }

    if module.check_mode:
        return result

    startd = datetime.datetime.now()
    changed = False

    # will return either the image name or None
    container_image = is_containerized()

    user = "client.admin"
    keyring_filename = cluster + '.' + user + '.keyring'
    user_key = os.path.join("/etc/ceph/", keyring_filename)

    if state == "present":
        rc, cmd, out, err = check_pool_exist(module, cluster, name, user, user_key, container_image=container_image)
        if rc == 0:
            running_pool_details = get_pool_details(module, cluster, name, user, user_key, container_image=container_image)
            delta = compare_pool_config(user_pool_config, running_pool_details[2])
            if len(delta) > 0:
                rc, cmd, out, err = update_pool(module, cluster, name, user, user_key, delta, container_image=container_image)
                if rc == 0:
                    changed = True
            else:
                out = "Pool {} already exists and there is nothing to update.".format(name)
        else:
            rc, cmd, out, err = exec_commands(module, create_pool(cluster, name, user, user_key, user_pool_config=user_pool_config, container_image=container_image))
            changed = True

    elif state == "list":
        rc, cmd, out, err = exec_commands(module, list_pools(cluster, name, user, user_key, details, container_image=container_image))
        if rc != 0:
            out = "Couldn't list pool(s) present on the cluster"

    else:
        module.fail_json(
            msg='State must either be "present" or "absent" or "list".', changed=False, rc=1)  # noqa E501


    exit_module(module=module, out=out, rc=rc, cmd=cmd, err=err, startd=startd, changed=changed)


def main():
    run_module()


if __name__ == '__main__':
    main()

