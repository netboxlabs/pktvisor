import configparser
from docker.errors import ImageNotFound
from hamcrest import *
import shlex
import subprocess
import docker


class TestConfig:
    _configs = None

    def __init__(self):
        raise RuntimeError('Call instance() instead')

    @classmethod
    def configs(cls):
        if cls._configs is None:
            cls._configs = _read_configs()
        return cls._configs


def _read_configs():
    parser = configparser.ConfigParser()
    parser.read('test_config.ini')
    configs = parser['test_config']
    super_user = configs.get('root', "none")
    if super_user.lower() == "true":
        configs['sudo'] = "False"
    else:
        configs['sudo'] = "True"
        assert_that(configs.get('sudo_password'), not_none(), 'Sudo password was not provided!')
    client = docker.from_env()
    configs['pktvisor_docker_image'] = f"netboxlabs/pktvisor:{configs.get('pktvisor_docker_image_tag', 'latest')}"
    try:
        client.images.get(configs['pktvisor_docker_image'])
    except ImageNotFound:
        client.images.pull(configs['pktvisor_docker_image'])
    return configs


def send_terminal_commands(command, separator=None, cwd_run=None, sudo="False"):
    assert_that(sudo, any_of(equal_to("False"), equal_to("True")), "Unexpected value for 'sudo' parameter")
    args = shlex.split(command)
    sudo_converter = {"False": False, "True": True}
    if sudo_converter[sudo] is False:
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdout=subprocess.PIPE, cwd=cwd_run, universal_newlines=True)
        subprocess_return_terminal = p.communicate()
    else:
        configs = TestConfig.configs()
        sudo_password = configs.get('sudo_password')
        p = subprocess.Popen(['sudo', '-S'] + args, stdin=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdout=subprocess.PIPE, cwd=cwd_run, universal_newlines=True)
        subprocess_return_terminal = p.communicate(sudo_password + '\n')
    return subprocess_return_terminal
