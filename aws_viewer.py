import boto.ec2
import time
import re
import cPickle
from os import stat
from os.path import isfile, expanduser
import ConfigParser


class Bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

class Aws:
    def __init__(self, config_file, region):
        self.config_file = config_file
        self._pickle_name = '/tmp/aws.' + region + '.pickle'
        self._instances = []
        self.get_configuration()
        if not self.is_cache_valid():
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

    def filter_instances(self, key, value):
        self._instances = [
                inst for inst in self.instances if key in inst.tags and inst.tags[key] == value]


    def get_all_tag_values(self, tag_name):
        values = set()
        for inst in self.instances:
            if tag_name in inst.tags and inst.tags[tag_name]:
                values.add(inst.tags[tag_name])
        return values


def ask_numeric_options(max_option):
    while True:
        selected = raw_input("Please enter option: ")
        if not re.match("^\d+$", selected) or int(selected) > max_option:
            print "Option %s is not valid option, try again" % selected
        else:
            return int(selected)

def print_list(name, options, all_option=True):
    print "Possible options of %s" % name
    if all_option:
        print '0) ALL'

    for num, option in enumerate(options):
        print "%s) %s" % (num + 1, option)

    selected = ask_numeric_options(len(options))

    if selected > 0:
        return options[selected-1]
    else:
        return False


def print_instances(instances):
    counter = {'running': 0, 'terminated': 0, 'shutting-down': 0, 'stopped': 0}
    print "%s%s" % (Bcolors.OKGREEN, '-'*111)
    print "| %11s |%12s |%18s |%15s |%10s |%14s |%15s |" % (
                                            'instance_id',
                                            'environment',
                                            'service',
                                            'role',
                                            'version',
                                            'state',
                                            'ip')
    print "%s" % '-'*111

    for inst in instances:
        counter[inst.state] += 1
        tags = inst.tags
        if inst.state == 'running':
            color = Bcolors.OKGREEN
        elif inst.state == 'terminated':
            color = Bcolors.FAIL
        elif inst.state == 'shutting-down':
            color = Bcolors.OKBLUE
        elif inst.state == 'stopped':
            color = Bcolors.WARNING

        print "%s| %11s |%12s |%18s |%15s |%10s |%14s |%15s |" % (
                                            color,
                                            inst.id,
                                            tags.get('environment', 'UNDEF'),
                                            tags.get('service', 'UNDEF'),
                                            tags.get('role', 'UNDEF'),
                                            tags.get('version', 'UNDEF'),
                                            inst.state,
                                            inst.private_ip_address)

    print "%s%s" % ('-'*111, Bcolors.ENDC)
    print "%s| TOTAL: %i | Running: %i | Stopped: %i | Terminated: %i |%s" % (
                                            Bcolors.OKGREEN,
                                            len(instances),
                                            counter['running'],
                                            counter['stopped'],
                                            counter['terminated'] + counter['shutting-down'],
                                            Bcolors.ENDC)


if __name__ == '__main__':
    config_file = '~/.aws_viewer'
    region = print_list('region', ['us-west-2', 'us-east-1'], False)

    aws = Aws(config_file, region)


    for tag in aws.tags:
        values = aws.get_all_tag_values(tag)
        result = print_list(tag, list(values))
        if result:
            aws.filter_instances(tag, result)


    print_instances(aws.instances)
