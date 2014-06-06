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


class ConfigError(Exception):
    pass


class Cache:
    def __init__(self, region, cache_timeout, cache_dir):
        self._cache_dir = cache_dir
        self._region = region
        self._cache_timeout = cache_timeout

    @property
    def cache_file(self):
        return "%s/aws.%s.pickle" % (self._cache_dir, self._region)

    def save(self, object):
        obj_to_save = {
            'object': object,
            'expired': time.time()
        }
        cPickle.dump(obj_to_save, open(self.cache_file, 'wb'))

    def load(self):
        try:
            cached_object = cPickle.load(open(self.cache_file, "rb"))
        except:
            return []

        if cached_object['expired'] > time.time() - self._cache_timeout:
            return cached_object['object']
        return []


class Config:
    config = dict()

    def __init__(self, config_file, cfg_keys, default_section='default'):
        self._default_section = default_section
        self._cfg_keys = cfg_keys
        self._dilimiter = ',\s*'

        self._config = ConfigParser.RawConfigParser()
        self._config.read(expanduser(config_file))
        self.get_configuration()

    def __get_key(self, key, attrs):

        if 'is_list' in attrs and attrs['is_list']:
            self.config[key] = re.split(self._dilimiter, getattr(self._config, attrs['method'])(self._default_section, key))
        else:
            self.config[key] = getattr(self._config, attrs['method'])(self._default_section, key)

    def get_configuration(self):

        for key, attrs in self._cfg_keys.iteritems():
            try:
                self.__get_key(key, attrs)
            except:
                if 'mandatory' in attrs and attrs['mandatory']:
                    raise ConfigError("Config key %s is mandatory" % key)
                if 'default' in attrs:
                    self.config[key] = attrs['default']


class Aws:
    def __init__(self, config, cache):
        self._instances = []
        self._cache_timeout = config['cache_timeout']
        self.cache = cache
        self.tags = config['tags']
        if cache:
            self._instances = self.cache.load()

        if not 'using_iam_role' in config or not config['using_iam_role']:
            self._aws_access_key_id = config['aws_access_key_id']
            self._aws_secret_access_key = config['aws_secret_access_key']
            self._using_iam_role = False
        else:
            self._using_iam_role = True

    def connect_to_region(self, region):
        self.region = region
        if not self._instances:
            if self._using_iam_role:
                self.conn = boto.ec2.connect_to_region(region)
            else:
                self.conn = boto.ec2.connect_to_region(region,
                            aws_access_key_id=self._aws_access_key_id,
                            aws_secret_access_key=self._aws_secret_access_key)

    @property
    def instances(self):
        if not self._instances:
            for res in self.conn.get_all_instances():
                for instance in res.instances:
                    self._instances.append(instance)
            if self.cache:
                self.cache.save(self._instances)
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

    if options:
        options.sort()

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

        print("%14s |%15s |%s" % (inst.state, inst.private_ip_address, Bcolors.ENDC))

    print("%s%s%s" % (Bcolors.default, '-' * field_len, Bcolors.ENDC))
    print_footer(len(instances), counter)

def print_footer(isnt_num, counter):
    print("%s| TOTAL: %i | Running: %i | Stopped: %i | Terminated: %i |%s" % (
                                            Bcolors.default,
                                            isnt_num,
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

    # describe configuration file
    cfg_keys = {
        'aws_access_key_id': { 'method': 'get'},
        'aws_secret_access_key': { 'method': 'get'},
        'cache_timeout': { 'method': 'getint', 'default': 30 },
        'tags': { 'method': 'get', 'is_list': True, 'mandatory': True },
        'using_iam_role': { 'method': 'getboolean' },
        'cache_dir': { 'method': 'get', 'default': '/tmp'},
        'regions': { 'method': 'get', 'is_list': True, 'default': ['us-west-2', 'us-east-1'] }
    }

    config = Config(options.config, cfg_keys).config

    if options.region:
        region = options.region
    else:
        region = print_list('region', config['regions'], False)[0]

    cache = Cache(region, config['cache_timeout'], config['cache_dir'])
    aws = Aws(config, cache)

    aws.connect_to_region(region)

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