from __future__ import print_function
import boto.ec2
import time
import re
import cPickle
from os import stat
from os.path import isfile, expanduser
import ConfigParser
import optparse


class Bcolors:
    shuttingdown = '\033[94m'
    running = '\033[92m'
    default = '\033[92m'
    stopped = '\033[93m'
    pending = '\033[93m'
    undefined = '\033[93m'
    terminated = '\033[91m'
    ENDC = '\033[0m'

class Aws:
    def __init__(self, config_file, region):
        self.config_file = config_file
        self._pickle_name = '/tmp/aws.' + region + '.pickle'
        self._instances = []
        self.get_configuration()
        if not self.is_cache_valid():
            if self._using_iam_role:
                self.conn = boto.ec2.connect_to_region(region)
            else:
                self.conn = boto.ec2.connect_to_region(region,
                           aws_access_key_id=self._aws_secret_key,
                           aws_secret_access_key=self._aws_secret_access_key)

    def get_configuration(self, default_section='default'):
        config = ConfigParser.RawConfigParser()
        config.read(expanduser(self.config_file))
        self._aws_secret_key = config.get(default_section, 'aws_secret_key')
        self._aws_secret_access_key = config.get(default_section, 'aws_secret_access_key')
        self._cache_timeout = config.getint(default_section, 'cache_timeout')
        self.tags = config.get(default_section, 'tags').replace(' ', '').split(',')
        self._using_iam_role = config.getboolean(default_section, 'using_iam_role')

    def is_cache_valid(self):
        if isfile(self._pickle_name):
            if stat(self._pickle_name).st_mtime > time.time() - self._cache_timeout:
                return True
        return False

    @property
    def instances(self):
        if not self._instances:
            if self.is_cache_valid():
                self._instances = cPickle.load(open(self._pickle_name, "rb"))
            else:
                for res in self.conn.get_all_instances():
                    for instance in res.instances:
                        self._instances.append(instance)
                cPickle.dump(self._instances, open(self._pickle_name, 'wb'))
        return self._instances

    def filter_instances(self, tag, values):
        result = list()

        for inst in self.instances:
            if tag in inst.tags:
                for value in values:
                    if inst.tags[tag] == value:
                        result.append(inst)
                        break

        self._instances = result

    def get_all_tag_values(self, tag_name):
        values = set()
        for inst in self.instances:
            if tag_name in inst.tags and inst.tags[tag_name]:
                values.add(inst.tags[tag_name])
        return values


def ask_numeric_options(max_option):
    while True:
        valid = True
        selected = raw_input("Please enter option: ")

        for option in selected.split(','):
            if not re.match("^\d+$", option) or int(option) > max_option:
                print("Option %s is not valid option, try again" % selected)
                valid = False
        if valid:
            return selected.split(',')


def print_list(name, options, all_option=True):
    print("Possible options of %s" % name)
    if all_option:
        print('0) ALL')

    for num, option in enumerate(options):
        print("%s) %s" % (num + 1, option))

    selected = ask_numeric_options(len(options))

    result = list()
    for choose in selected:
        if int(choose) == 0:
            return False
        else:
            result.append(options[int(choose)-1])

    return result


def print_instances(instances, tag_list):
    counter = {'running': 0, 'terminated': 0, 'shutting-down': 0, 'stopped': 0, 'pending': 0}
    field_len = 48 + 17 * len(tag_list)
    print("%s%s" % (Bcolors.default, '-' * field_len))
    print("| %11s |" % 'instance_id', end='')

    for tag in tag_list:
        print("%15s |" % tag, end='')

    print("%14s |%15s |" % ('state', 'ip'))

    print("%s" % '-' * field_len)
    for inst in instances:
        counter[inst.state] += 1
        tags = inst.tags
        color = inst.state.replace('-','')

        print("%s| %11s |" % (getattr(Bcolors, color, 'undefined'), inst.id), end='')

        for tag in tag_list:
            print("%15s |" % tags.get(tag, 'UNDEF'), end="")

        print("%14s |%15s |" % (inst.state, inst.private_ip_address))

    print("%s%s" % ('-' * field_len, Bcolors.ENDC))
    print("%s| TOTAL: %i | Running: %i | Stopped: %i | Terminated: %i |%s" % (
                                            Bcolors.default,
                                            len(instances),
                                            counter['running'],
                                            counter['stopped'],
                                            counter['terminated'] + counter['shutting-down'],
                                            Bcolors.ENDC))


if __name__ == '__main__':
    parser = optparse.OptionParser()

    parser.add_option('-a', '--all', action="store_true", dest='all', help='print all instances')
    parser.add_option('-r', '--region', help='region name')
    parser.add_option('-t', '--tags', help='tags list')
    parser.add_option('-c', '--config', help='config file', default='~/.aws_viewer')

    options, args = parser.parse_args()
    possible_regions = ['us-west-2', 'us-east-1']

    if options.region:
        region = options.region
    else:
        region = print_list('region', possible_regions, False)[0]

    aws = Aws(options.config, region)
    tags = options.tags.split(',') if options.tags else aws.tags

    if options.all:
        aws.instances
    else:
        for tag in tags:
            possible_values = aws.get_all_tag_values(tag)
            chosen_values = print_list(tag, list(possible_values))
            if chosen_values:
                aws.filter_instances(tag, chosen_values)

    print_instances(aws.instances, tags)