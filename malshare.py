#!/usr/bin/env python3
import argparse
import logging
import os
import glob
import hashlib
import platform
import time
import typing
from enum import Enum

import requests
import requests.adapters
import requests.exceptions

__version__ = '1.1.0'


class Guid:
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return F'<Guid {self.value}>'


class Digests:
    def __init__(self, sha256, md5, sha1):
        self.sha256 = sha256
        self.md5 = md5
        self.sha1 = sha1

    @staticmethod
    def from_file_name(file_name, block_size=0x400):
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        sha1 = hashlib.sha1()
        with open(file_name, 'rb') as f:
            while True:
                block = f.read(block_size)
                if not block:
                    break
                md5.update(block)
                sha256.update(block)
                sha1.update(block)

        return Digests(sha256.hexdigest(), md5.hexdigest(), sha1.hexdigest())

    def __eq__(self, other):
        return self.sha256 == other.sha256 and self.md5 == other.md5 and self.sha1 == other.sha1


class DownloadUrlStatus(Enum):
    # task with specified GUID does not exist
    MISSING = 1

    # task was submitted but not picked up yet
    PENDING = 2

    # download in progress
    PROCESSING = 3

    # job finished
    FINISHED = 4

    # unknown status
    UNKNOWN = 5

    @staticmethod
    def from_string(status: str):
        if status == 'missing':
            return DownloadUrlStatus.MISSING
        elif status == 'pending':
            return DownloadUrlStatus.PENDING
        elif status == 'processing':
            return DownloadUrlStatus.PROCESSING
        elif status == 'finished':
            return DownloadUrlStatus.FINISHED


class ApiException(Exception):
    pass


class ApiKeyInvalidException(ApiException):
    pass


class Api500Exception(ApiException):
    pass


class FixedTimeoutAdapter(requests.adapters.HTTPAdapter):
    def send(self, *pargs, **kwargs):
        if kwargs['timeout'] is None:
            kwargs['timeout'] = 10
        return super(FixedTimeoutAdapter, self).send(*pargs, **kwargs)


class MalShareApi:
    def __init__(self, base_url, api_key, user_agent):
        self.base_url = base_url
        self.api_key = api_key
        self.session = requests.session()
        self.session.mount('https://', FixedTimeoutAdapter())
        self.session.mount('http://', FixedTimeoutAdapter())
        self.session.headers = {'User-Agent': user_agent}

    def download(self, sample_hash):
        response = self.session.get(F'{self.base_url}?api_key={self.api_key}&action=getfile&hash={sample_hash}')
        if response.status_code == 401:
            raise ApiKeyInvalidException(response.content)
        elif response.status_code == 404:
            if response.content.startswith(b'Sample not found by hash'):
                return None
            else:
                raise ApiException(F'Status-Code: {response.status_code}: {response.content}')
        elif response.status_code != 200:
            raise ApiException(F'Status-Code: {response.status_code}: {response.content}')
        return response.content

    def details(self, sample_hash):
        response = self.session.get(F'{self.base_url}?api_key={self.api_key}&action=details&hash={sample_hash}')
        if response.status_code == 400:
            raise ApiKeyInvalidException(response.json()['ERROR']['MESSAGE'])
        elif response.status_code == 401:
            raise ApiKeyInvalidException(response.content)
        elif response.status_code == 404:
            if response.json()['ERROR']['MESSAGE'] == 'Sample not found':
                return None
            else:
                raise ApiException(F'Status-Code: {response.status_code}: {response.content}')
        elif response.status_code != 200:
            raise ApiException(F'Status-Code: {response.status_code}: {response.content}')
        return response.json()

    def upload(self, upload_data):
        response = self.session.post(
            F'{self.base_url}?api_key={self.api_key}&action=upload',
            files={'upload': upload_data}
        )
        if response.status_code == 500:
            raise Api500Exception(response.content.decode('utf-8'))
        if response.status_code != 200:
            raise ApiException(F'Status-Code: {response.status_code}: {response.content}')
        return response.content

    def check_hashes(self, sample_hashes: typing.List[str]) -> typing.List[Digests]:
        response = self.session.post(
            F'{self.base_url}?api_key={self.api_key}&action=hashlookup',
            data='\n'.join(sample_hashes)
        )
        if response.status_code != 200:
            raise ApiException(F'Status-Code: {response.status_code}: {response.content}')
        return [Digests(row['sha256'], row['md5'], row['sha1']) for row in response.json()]

    def download_url(self, url: str) -> Guid:
        response = self.session.post(
            F'{self.base_url}?api_key={self.api_key}&action=download_url',
            data={'url': url}
        )
        if response.status_code != 200:
            raise ApiException(F'Status-Code: {response.status_code}: {response.content}')
        return Guid(response.json()['guid'])

    def download_status(self, guid: Guid) -> DownloadUrlStatus:
        try:
            response = self.session.get(
                F'{self.base_url}?api_key={self.api_key}&action=download_url_check&guid={guid.value}'
            )
        except requests.exceptions.ConnectionError:
            return DownloadUrlStatus.UNKNOWN

        if response.status_code != 200:
            raise ApiException(F'Status-Code: {response.status_code}: {response.content}')
        return DownloadUrlStatus.from_string(response.json()['status'])


class ConsoleHandler(logging.Handler):
    def emit(self, record):
        print('[%s] %s' % (record.levelname, record.msg))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--user-agent',
        default=F'MalShareClient/{__version__} (python-requests {requests.__version__}) '
                F'{platform.system()} ({platform.release()})'
    )
    subparsers = parser.add_subparsers(dest='command')

    download_parser = subparsers.add_parser(
        'download',
        help='Specify a SHA256, MD5 or SHA1 hash. Corresponding sample will be downloaded from MalShare if present '
             'and stored in the current directory'
    )
    download_parser.add_argument('hashes', nargs='+', help='Hex-encoded form of SHA256, MD5 or SHA1 hashes')
    download_parser.add_argument('--file-name', help='use this file name instead of hash')

    upload_parser = subparsers.add_parser(
        'upload',
        help='Specify one or more files, they will be uploaded to and published (!) on MalShare'
    )
    upload_parser.add_argument(
        '--bulk', action='store_true',
        help='First hash all files to be uploaded and check if they already exist.'
    )
    upload_parser.add_argument('file_names', nargs='+', help='Name of files to be uploaded.')

    upload_parser = subparsers.add_parser('url', help='Task download of specified URL on MalShare.')
    upload_parser.add_argument('url', help='URL to download. Will be touched by the service.')
    upload_parser.add_argument('--poll-sleep', help='Seconds between polls.', default=5)

    parser.add_argument(
        '--base-url', help='Overwrite URL',
        default=os.getenv('MALSHARE_BASE_URL', 'https://malshare.com/api.php')
    )
    parser.add_argument('--api-key', default=os.getenv('MALSHARE_API_KEY', None))
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    logger = logging.getLogger('MalShareClient')
    logger.handlers.append(ConsoleHandler())
    logger.setLevel(logging.DEBUG if args.debug else logging.INFO)

    api = MalShareApi(args.base_url, args.api_key, args.user_agent)
    try:
        if args.command == 'download':
            for i, hash_to_download in enumerate(args.hashes):
                hash_to_download = hash_to_download.strip()
                if args.file_name:
                    target_file_name = args.file_name
                    if args.file_name and len(args.hashes) > 1:
                        target_file_name = F'{target_file_name}-{i}'
                else:
                    target_file_name = hash_to_download

                if os.path.exists(target_file_name):
                    logger.info(F'File with name {target_file_name} already exists, skipping.')
                else:
                    download_data = api.download(hash_to_download)
                    if download_data is None:
                        logger.error(F'File with hash {hash_to_download} not found.')
                    else:
                        with open(target_file_name, 'wb') as fp:
                            fp.write(download_data)
                        logger.info(F'Downloaded {len(download_data)} bytes to {target_file_name}.')
        elif args.command == 'upload':
            if args.bulk:
                digests = {}
                for pattern in args.file_names:
                    for source_file_name in glob.glob(pattern):
                        if os.path.exists(source_file_name):
                            logger.debug(F'Hashing "{source_file_name}"...')
                            digests[source_file_name] = Digests.from_file_name(source_file_name)
                logger.debug(F'Checking existence of {len(digests)} hashes.')
                existing = api.check_hashes([digest.sha256 for digest in digests.values()])
                file_names_to_upload = [
                    source_file_name for source_file_name, current_hash in digests.items()
                    if current_hash not in existing
                ]
                logger.debug(F'Uploading {len(file_names_to_upload)} files now.')
                for source_file_name in file_names_to_upload:
                    logger.debug(F'Uploading "{source_file_name}"...')
                    with open(source_file_name, 'rb') as fp:
                        api.upload(fp.read())
            else:
                for pattern in args.file_names:
                    for source_file_name in glob.glob(pattern):
                        logger.debug(F'Uploading {source_file_name}')
                        if os.path.exists(source_file_name):
                            with open(source_file_name, 'rb') as fp:
                                data = fp.read()
                            current_hash = hashlib.sha256(data).hexdigest()
                            details = api.details(current_hash)
                            if details is not None:
                                logger.info(
                                    F'Sample "{source_file_name}" already present (SHA256: {current_hash}), skipping.'
                                )
                                continue
                            try:
                                upload_response = api.upload(data)
                                if upload_response.startswith(b'Success -'):
                                    logger.info(F'Successfully uploaded "{source_file_name}" (SHA256: {current_hash}).')
                                else:
                                    logger.error(F'Unknown error uploading "{source_file_name}": {upload_response}')
                            except Api500Exception as e:
                                logger.error(F'While uploading {source_file_name}: {str(e).encode("utf-8")}')
                        else:
                            logger.error(F'Cannot find file with name "{source_file_name}". Skipping.')
        elif args.command == 'url':
            logger.debug(F'Tasking download of "{args.url}"...')
            task_id = api.download_url(args.url)
            while True:
                current_status = api.download_status(task_id)
                logger.debug(F'Polling status: {current_status}')
                if current_status == DownloadUrlStatus.FINISHED:
                    break
                time.sleep(args.poll_sleep)

    except ApiKeyInvalidException as e:
        logger.exception(e)
