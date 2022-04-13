from P4 import P4, P4Exception
from functools import wraps
import os
import re
import logging
from collections import OrderedDict

logger = logging.getLogger(__name__)


class PathNotInClientViewError(P4Exception):
    pass


class P4ClientOverwriteError(P4Exception):
    pass


class P4ConnectResetException(P4Exception):
    @staticmethod
    def catch(msg):
        patterns = [
            'TCP send failed.*(WSAECONNRESET|Broken pipe)',
            'Partner exited unexpectedly',
            'TCP receive failed',
            'socket: Connection reset by peer',
        ]
        match = re.search('|'.join(patterns), msg, re.DOTALL)
        if match:
            return P4ConnectResetException(msg)


class P4NotConnectedException(P4Exception):
    @staticmethod
    def catch(msg):
        match = re.search('P4\.run.*not connected', msg)
        if match:
            return P4NotConnectedException('P4 not connected')


class P4ConnectErrorException(P4Exception):
    @staticmethod
    def catch(msg):
        match = re.search('TCP connect to (\S+:\d+) failed', msg)
        if match:
            port = match.group(1)
            return P4ConnectErrorException(f'Connect to p4 failed, P4PORT: {port}')


class P4FileNotExistException(P4Exception):
    @staticmethod
    def catch(msg):
        match = re.search("\[Warning]: '(.*) - file\(s\) not in client view", msg)
        if not match:
            match = re.search("\[Warning]: '(.*) - no such file\(s\)", msg)
        if match:
            file_path = match.group(1)
            return P4FileNotExistException("p4上未找到文件 - %s" % file_path)


class P4LoginErrorException(P4Exception):
    @staticmethod
    def catch(msg):
        match = re.search('p4 login.*Password invalid', msg, re.DOTALL)
        if match:
            return P4LoginErrorException("Password invalid")
        match = re.search("p4 login.*User (.*) doesn't exist", msg, re.DOTALL)
        if match:
            user_name = match.group(1)
            return P4LoginErrorException(f"User {user_name} doesn't exist")


class P4NotLoginException(P4Exception):
    @staticmethod
    def catch(msg):
        match = re.search('Perforce password \(P4PASSWD\) invalid or unset', msg)
        if match:
            return P4NotLoginException(msg)


class P4NotRevertedException(P4Exception):
    @staticmethod
    def catch(msg):
        match = re.search('Out of date files must be resolved or reverted', msg)
        if match:
            return P4NotRevertedException(msg)


def redefine_p4exception(method):
    """捕获所有的P4Exception异常，根据异常信息，匹配上面自定义的异常后抛出，为后面P4Client类中根据不同类型的异常做相应的处理服务"""
    @wraps(method)
    def inner_fun(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except P4Exception as e:
            ignore_error_patterns = [
                "\[Warning]: '(.*) - file\(s\) up-to-date",
                "p4 revert.*\[Warning]: '(.*) - file\(s\) not opened on this client",
            ]
            for ignore_error_pattern in ignore_error_patterns:
                if re.search(ignore_error_pattern, str(e), re.DOTALL):
                    return str(e)

            error = P4NotConnectedException.catch(str(e))
            if error:
                raise error

            error = P4ConnectResetException.catch(str(e))
            if error:
                raise error

            error = P4ConnectErrorException.catch(str(e))
            if error:
                raise error

            error = P4NotLoginException.catch(str(e))
            if error:
                raise error

            error = P4LoginErrorException.catch(str(e))
            if error:
                raise error

            error = P4FileNotExistException.catch(str(e))
            if error:
                raise error

            error = P4NotRevertedException.catch(str(e))
            if error:
                raise error

            raise
    return inner_fun


class P4Config:
    def __init__(self, user, password, port, workspace=None, exception_level=P4.RAISE_ALL):
        self.user = user
        self.password = password
        self.port = port
        self.workspace = workspace
        self.exception_level = exception_level


def init_p4(p4config):
    """
    初始化P4
    """
    p4 = P4()
    p4.user = p4config.user
    p4.password = p4config.password
    p4.port = p4config.port
    if p4config.workspace:
        p4.client = p4config.workspace
    p4.exception_level = p4config.exception_level
    return p4


class P4Client:
    def __init__(self, user, password, client, client_config: dict, port='p4.com:2002'):
        """
        初始化p4，如果client已存在，则直接获取client,如果client不存在，则使用client_config配置创建client并保存
        :param user: 用户名
        :param password: 密码
        :param client: p4 workspace 名称
        :param client_config: client配置信息，可以配置client的 root,Description,View等信息
        :param port: p4 服务器地址
        """
        logger.info('Init P4 ...')
        self.p4config = P4Config(user, password, port, client)
        self._p4 = init_p4(self.p4config)
        if not client:
            self.p4config.workspace = self._p4.client
        logger.info(self.connect())
        logger.info(self.login())

        # 更新p4 workspace配置
        if not self.is_client_exist(client):
            self.client = self._p4.fetch_client()
            self.client.update(client_config)
            self._p4.save_client(self.client)
            self.client = self._p4.fetch_client()
        else:
            self.client = self._p4.fetch_client()
        # self.client = self._p4.fetch_client()
        # self.client.update(client_config)
        # self._p4.save_client(self.client)
        # self.client = self._p4.fetch_client()

        self.root = self.client['Root']
        self.file_map_of_view, self.ordered_dir_map_of_view = self.get_file_map_and_ordered_dir_map_from_view()
        self.is_windows = (os.name == 'nt')
        logger.info(self.client)

    def recreate_p4_connection(self):
        logger.info('Recreate P4 connection ...')
        self._p4 = init_p4(self.p4config)
        logger.info(self.connect())
        logger.info(self.__login())
        self.client = self._p4.fetch_client()
        logger.info(self.client)
        return self.client

    def get_p4config_info(self):
        return self.p4config.__dict__

    def is_client_exist(self, client_name):
        results = self.run_clients('-e', client_name)
        return len(results) >= 1

    def get_cwd(self):
        return self._p4.cwd

    def get_root(self):
        return self.root

    def get_view(self):
        return self.client['View']

    def get_file_map_and_ordered_dir_map_from_view(self):
        file_map = dict()
        dir_map = OrderedDict()
        dir_paris = list()
        view = self.client['View']
        for s in view:
            p4_path, client_p4_path = s.split()
            if p4_path.endswith('...'):
                dir_paris.append((p4_path[:-3], client_p4_path[:-3]))
            else:
                file_map[p4_path] = client_p4_path
        dir_paris.sort(key=lambda item: len(item[0].split('/')), reverse=True)
        for p4_path, client_p4_path in dir_paris:
            dir_map[p4_path] = client_p4_path
        return file_map, dir_map

    def to_local_path(self, p4_path):
        client_p4_path = self.p4_path_to_client_p4_path(p4_path)
        return self.client_p4_path_to_local_path(client_p4_path)

    def to_p4_path(self, local_path):
        client_p4_path = self.local_path_to_client_p4_path(local_path)
        return self.client_p4_path_to_p4_path(client_p4_path)

    def local_path_to_client_p4_path(self, local_path):
        if self.is_windows:
            if abs(ord(local_path[0]) - ord(self.root[0])) == 32:  # 统一首字母（盘符）大小写
                local_path = local_path.replace(local_path[0], self.root[0], 1)
        raise_error = False
        if local_path.startswith(self.root):
            if len(local_path) > len(self.root):
                char = local_path[len(self.root)]
                if self.is_windows:
                    raise_error = char != '\\'
                else:
                    raise_error = char != '/'
        else:
            raise_error = True
        if raise_error:
            raise PathNotInClientViewError("'%s' 不在 p4 client 的根目录下" % local_path)
        workspace = self.p4config.workspace
        client_p4_path = f'//{workspace}' + local_path[len(self.root):]
        if '\\' in client_p4_path:
            client_p4_path = client_p4_path.replace('\\', '/')
        return client_p4_path

    def client_p4_path_to_local_path(self, client_p4_path):
        workspace = self.p4config.workspace
        local_path = client_p4_path.replace(f'//{workspace}', self.root, 1)
        if self.is_windows:
            local_path = local_path.replace('/', '\\')
        return local_path

    def p4_path_to_client_p4_path(self, p4_path: str):
        if p4_path in self.file_map_of_view:
            return self.file_map_of_view[p4_path]
        else:
            for key, value in self.ordered_dir_map_of_view.items():
                if p4_path.startswith(key):
                    client_p4_path = p4_path.replace(key, value, 1)
                    return client_p4_path
        raise PathNotInClientViewError("'%s' is not in client view" % p4_path)

    def client_p4_path_to_p4_path(self, client_p4_path: str):
        client_file_map = {value: key for key, value in self.file_map_of_view.items()}
        if client_p4_path in client_file_map:
            return client_file_map[client_p4_path]
        else:
            for key, value in self.ordered_dir_map_of_view.items():
                if client_p4_path.startswith(value):
                    p4_path = client_p4_path.replace(value, key, 1)
                    return p4_path
        raise PathNotInClientViewError("'%s' is not in client view" % client_p4_path)

    @redefine_p4exception
    def connect(self):
        return self._p4.connect()

    def disconnect(self):
        getattr(self, '__disconnect')()
        return 'Client has been disconnected'

    def handle_exception(self, method, name):
        """装饰p4的原方法，增加对错误的处理机制"""
        @wraps(method)
        def inner_method(*args, **kwargs):
            try:
                return method(*args, **kwargs)
            except P4NotConnectedException:
                self.connect()
                self.__login()
                return method(*args, **kwargs)
            except P4NotLoginException:
                self.__login()
                return method(*args, **kwargs)
            except P4ConnectResetException:
                self.recreate_p4_connection()
                f = getattr(self, '__' + name)
                return f(*args, **kwargs)

        return inner_method

    def __getattr__(self, name):
        if name.startswith('__'):
            f = getattr(self._p4, name[2:])
            if type(f).__name__ not in ['function', 'method', 'builtin_function_or_method']:
                return f

            @redefine_p4exception
            def inner_fun(*args, **kwargs):
                return f(*args, **kwargs)
            return inner_fun
        else:
            f = getattr(self, '__' + name)
            if type(f).__name__ not in ['function', 'method', 'builtin_function_or_method']:
                return f
            return self.handle_exception(f, name)

    @redefine_p4exception
    def __login(self):
        return self._p4.run_login(user=self.p4config.user, password=self.p4config.password)

    def login(self):
        try:
            return self.__login()
        except P4NotConnectedException:
            self.connect()
            return self.__login()
        except P4ConnectResetException:
            self.recreate_p4_connection()
            return self.__login()

    def domain(self, p4path):
        return P4Domain(self, p4path)

    def get_content(self, file_p4path):
        from flask import send_from_directory
        with self.domain(file_p4path):
            dir_path, filename = os.path.split(self.to_local_path(file_p4path))
            return send_from_directory(dir_path, filename)

    def sync(self, *args, **kwargs):
        # if not self.is_windows:
        #     for arg in args:
        #         if has_chinese(arg):
        #             return self.sync_chinese(arg)
        kwargs['encoding'] = 'gbk'
        return self.run_sync(*args, **kwargs)

    def sync_chinese(self, p4_path):
        from ..config import bin_dir
        import subprocess
        if self.is_windows:
            return self.sync('-f', p4_path)
        else:
            p4_cn_full_path = os.path.join(bin_dir, 'p4cn')
            logger.info(f'[sync_chinese] {p4_cn_full_path}')
            shell_script = f"""chmod +x {p4_cn_full_path};{p4_cn_full_path} sync -P {self.p4config.password} -u {self.p4config.user} -c {self.p4config.workspace} -p {self.p4config.port} {p4_path}"""
            # subprocess.Popen(shell_script, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            logger.info(shell_script)
            result = subprocess.check_output(["/bin/sh", "-c", shell_script], stderr=subprocess.STDOUT)
            import pdb
            pdb.set_trace()
            return result

    def sync_dir(self, p4_dir_path: str, *options):
        p4_dir_path = self.__format_p4_dir(p4_dir_path)
        return self.sync(*options, p4_dir_path)

    @staticmethod
    def __format_p4_dir(p4_dir_path, appendix='...'):
        if p4_dir_path.endswith('/'):
            p4_dir_path += appendix
        else:
            if p4_dir_path.endswith('/*'):
                p4_dir_path = p4_dir_path[:-1] + appendix
            elif p4_dir_path.endswith('/...'):
                p4_dir_path = p4_dir_path[:-3] + appendix
            else:
                p4_dir_path += '/' + appendix
        return p4_dir_path

    def exists(self, p4_path):
        if self.is_dir(p4_path):
            return self.does_dir_exist(p4_path)
        try:
            self.files(p4_path)
            return True
        except P4FileNotExistException:
            return self.does_file_exist(p4_path)

    @staticmethod
    def is_dir(p4_path: str) -> bool:
        if p4_path.endswith('/*') or p4_path.endswith('/...') or p4_path.endswith('/'):
            return True
        return False

    def does_dir_exist(self, p4_dir_path: str):
        try:
            self.files(p4_dir_path)
            return True
        except P4FileNotExistException:
            return False

    def does_file_exist(self, p4_file_path):
        p4_dir, _ = os.path.split(p4_file_path)
        try:
            files = self.files(p4_dir)
            for file_info in files:
                if file_info['depotFile'].lower() == p4_file_path.lower():
                    return True
            return False
        except P4FileNotExistException:
            return False

    def dirs(self, *p4_dir_paths) -> list:
        """获取该目录所有的子目录信息列表（非递归）"""
        p4_dir_paths = (self.__format_p4_dir(p4_dir_path, appendix='*') for p4_dir_path in p4_dir_paths)
        return self.run_dirs(*p4_dir_paths)

    def files(self, p4_dir_path, **kwargs) -> list:
        """获取目录及其子目录下所有的文件信息列表"""
        kwargs['encoding'] = 'gbk'
        p4_dir_path = self.__format_p4_dir(p4_dir_path)
        return self.run_files('-e', p4_dir_path, **kwargs)

    def submit(self, desc: str, *args, **kwargs):
        kwargs['encoding'] = 'gbk'
        try:
            return self.run_submit('-d', desc, *args, **kwargs)
        except P4NotRevertedException:
            self.run_revert('//...')
            raise

    def add(self, *args, **kwargs):
        return self.run_add(*args, **kwargs)

    def edit(self, *args, **kwargs):
        return self.run_edit(*args, **kwargs)

    def delete(self, p4_path):
        return self.run_delete('-c', 'default', '-v', p4_path)

    def overwrite(self, file_path, content=None, content_path=None, read_mode='rb', write_mode='wb'):
        """编辑指定文件，覆盖原有内容"""
        if content is None:
            if content_path is None:
                raise P4ClientOverwriteError("参数content 和 content_path 值不能同时为空")
            with open(content_path, mode=read_mode) as f:
                content = f.read()
        res = self.edit(file_path)
        local_path = self.to_local_path(file_path)
        with open(local_path, mode=write_mode) as f:
            f.write(content)
        return res

    def describe(self, changelist_num: str):
        """
        获取指定版本号的文件变更详细信息
        :param changelist_num: 提交版本号
        :return: dict
        """
        result = self.run_describe(changelist_num)
        return result[0]

    def describe_many(self, *changelist_nums):
        """
        获取多个版本号的文件变更详细信息
        :param changelist_nums: 提交版本号列表
        :return: list
        """
        return self.run_describe(*changelist_nums)


class P4Domain(object):
    def __init__(self, p4: P4Client, p4path):
        self.p4 = p4
        self.p4path = p4path
        self.domain_dir = ''
        if not self.p4.is_windows:
            if self.p4.does_dir_exist(p4path):
                local_dir_path = p4.to_local_path(p4path)
                self.domain_dir = self.get_chinese_dir(local_dir_path) or local_dir_path
            else:
                self.domain_dir = self.get_chinese_dir(p4.to_local_path(p4path))

    def __enter__(self):
        if self.domain_dir:
            convmv_gbk_to_utf8(self.domain_dir)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.domain_dir:
            convmv_utf8_to_gbk(self.domain_dir)

    @staticmethod
    def get_chinese_dir(local_path) -> str:
        parts = local_path.split(os.path.sep)
        i = 0
        while i < len(parts):
            if has_chinese(parts[i]):
                break
            i += 1
        else:
            return ''
        local_chinese_dir = os.path.sep.join(parts[:i])
        return local_chinese_dir


def has_chinese(string):
    """
    检查整个字符串是否包含中文
    :param string: 需要检查的字符串
    :return: bool
    """
    for ch in string:
        if u'\u4e00' <= ch <= u'\u9fff':
            return True
    return False


def convmv_gbk_to_utf8(local_chinese_dir):
    os.system(f'convmv -f gbk -t utf-8 "{local_chinese_dir}"/* -r --notest --replace')


def convmv_utf8_to_gbk(local_chinese_dir):
    os.system(f'convmv -t gbk -f utf-8 "{local_chinese_dir}"/* -r --notest --replace')

