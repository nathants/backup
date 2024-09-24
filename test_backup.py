import shell as sh
import os
import re
import uuid
import json

sh.set['stream'] = True



assert os.environ['GIT_REMOTE_AWS_TEST_ACCOUNT'] == sh.run('libaws aws-account')

def scrub(text):
    text = re.sub(r'\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}Z', 'DATE', text) # remove digits from date
    text = re.sub(r'(\w{8})\w{120}', r'\1', text) # truncate blake2b
    return text

def scrub2(text):
    text = re.sub(r'\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}Z', 'DATE', text) # remove digits from date
    text = re.sub(r'\w{128}', 'HASH', text) # remove blake2b
    return text

def diff():
    return [(kind, path, tar, blake2b, size, mode) for x in scrub(sh.run('backup-diff')).splitlines() for kind, path, tar, blake2b, size, mode in [x.split()]]

def additions():
    return [(path, tar, blake2b, size, mode) for x in scrub(sh.run('backup-additions')).splitlines() for path, tar, blake2b, size, mode in [x.split()]]

def log():
    return scrub2(sh.run('backup-log --pretty=%s index')).splitlines()

def commits():
    return sh.run('backup-log --pretty=%H index').splitlines()

def index():
    return [(path, tar, blake2b, size, mode) for x in scrub(sh.run('backup-index')).splitlines() for path, tar, blake2b, size, mode in [x.split()]]

def find(regex, revision='HEAD'):
    out = sh.run(f"backup-find '{regex}' {revision}")
    out = scrub(out)
    return [(path, tar, blake2b, size, mode) for x in out.splitlines() for path, tar, blake2b, size, mode in [x.split()]]

def restore(regex, revision='HEAD'):
    return [(path, blake2b[:8]) for x in sh.run(f"backup-restore '{regex}' {revision}").splitlines() for path, blake2b in [x.split()]]

def test_basic():
    with sh.tempdir():
        uid = str(uuid.uuid4())
        os.environ['BACKUP_GIT'] = os.environ['BACKUP_TEST_GIT']
        os.environ['BACKUP_S3'] = os.environ['BACKUP_TEST_S3']
        os.environ['BACKUP_CHUNK_MEGABYTES'] = '100'
        os.environ['BACKUP_ROOT'] = os.getcwd()
        sh.run('libaws s3-rm', os.environ['BACKUP_S3'].split('s3://')[-1].split('/')[0] + '/', '-r')
        sh.run('libaws dynamodb-item-rm-all', os.environ['BACKUP_GIT'].split('+')[-1].split('/')[0], 'id')
        for k, v in os.environ.items():
            if k.startswith('BACKUP_'):
                print(k, '=>', v)
        sh.run('echo foo > bar.txt')
        sh.run('backup-add')
        assert diff() == [
            ('addition:', './bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
        ]
        assert additions() == [
            ('./bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
        ]
        sh.run('backup-commit')
        assert log() == [
            '0000000000.DATE.tar.lz4.enc.00000 HASH 549',
            'init',
        ]
        assert index() == [
            ('./bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
        ]
        sh.run('echo foo > bar2.txt')
        sh.run('backup-add')
        assert diff() == [
            ('addition:', './bar2.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
        ]
        assert additions() == [
            ('./bar2.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
        ]
        sh.run('backup-commit')
        assert log() == [
            'index-only-update',
            '0000000000.DATE.tar.lz4.enc.00000 HASH 549',
            'init',
        ]
        assert index() == [
            ('./bar.txt',  '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
            ('./bar2.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
        ]
        sh.run('echo asdf > asdf.txt')
        sh.run('backup-add')
        assert diff() == [
            ('addition:', './asdf.txt', '0000000001.DATE.tar.lz4.enc.00000', '36b807d5', '5', '644')
        ]
        assert additions() == [
            ('./asdf.txt', '0000000001.DATE.tar.lz4.enc.00000', '36b807d5', '5', '644')
        ]
        sh.run('backup-commit')
        assert log() == [
            '0000000001.DATE.tar.lz4.enc.00000 HASH 552',
            'index-only-update',
            '0000000000.DATE.tar.lz4.enc.00000 HASH 549',
            'init',
        ]
        assert index() == [
            ('./asdf.txt', '0000000001.DATE.tar.lz4.enc.00000', '36b807d5', '5', '644'),
            ('./bar.txt',  '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
            ('./bar2.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
        ]
        with sh.tempdir():
            os.environ['BACKUP_ROOT'] = os.getcwd()
            _ = find('.') # clone the repo with the first call to find()
            assert [find('.', commit) for commit in commits()] == [find(r'\.txt$', commit) for commit in commits()] == [
                [
                    ('./asdf.txt', '0000000001.DATE.tar.lz4.enc.00000', '36b807d5', '5', '644'),
                    ('./bar.txt',  '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
                    ('./bar2.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
                ],
                [
                    ('./bar.txt',  '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
                    ('./bar2.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
                ],
                [
                    ('./bar.txt',  '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
                ],
                [],
            ]
            assert [find('.*asdf.*', commit) for commit in commits()] == [
                [
                    ('./asdf.txt', '0000000001.DATE.tar.lz4.enc.00000', '36b807d5', '5', '644'),
                ],
                [],
                [],
                [],
            ]
        with sh.tempdir():
            os.environ['BACKUP_ROOT'] = os.getcwd()
            _ = find('.')
            assert [restore('.', commit) for commit in commits()] == [
                [
                    ('./bar.txt',  'd202d795'),
                    ('./bar2.txt', 'd202d795'),
                    ('./asdf.txt', '36b807d5'),
                ],
                [
                    ('./bar.txt',  'd202d795'),
                    ('./bar2.txt', 'd202d795'),
                ],
                [
                    ('./bar.txt',  'd202d795'),
                ],
                [],
            ]
            assert [restore(r'\./bar2\.txt$', commit) for commit in commits()] == [
                [
                    ('./bar2.txt', 'd202d795'),
                ],
                [
                    ('./bar2.txt', 'd202d795'),
                ],
                [],
                [],
            ]
            assert sh.run('cat bar.txt') == 'foo'
            assert sh.run('cat bar2.txt') == 'foo'
            assert sh.run('cat asdf.txt') == 'asdf'

def test_symlink():
    with sh.tempdir():
        uid = str(uuid.uuid4())
        os.environ['BACKUP_GIT'] = os.environ['BACKUP_TEST_GIT']
        os.environ['BACKUP_S3'] = os.environ['BACKUP_TEST_S3']
        os.environ['BACKUP_CHUNK_MEGABYTES'] = '100'
        os.environ['BACKUP_ROOT'] = os.getcwd()
        sh.run('libaws s3-rm', os.environ['BACKUP_S3'].split('s3://')[-1].split('/')[0] + '/', '-r')
        sh.run('libaws dynamodb-item-rm-all', os.environ['BACKUP_GIT'].split('+')[-1].split('/')[0], 'id')
        for k, v in os.environ.items():
            if k.startswith('BACKUP_'):
                print(k, '=>', v)
        ##
        sh.run('echo foo > bar.txt')
        sh.run('ln -s bar.txt link.txt')
        sh.run('backup-add')
        assert diff() == [
            ('addition:', './bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
            ('addition:', './link.txt', 'symlink', './bar.txt', '0', '-'),
        ]
        assert additions() == [
            ('./bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
            ('./link.txt', 'symlink', './bar.txt', '0', '-'),
        ]
        sh.run('backup-commit')
        assert log() == [
            '0000000000.DATE.tar.lz4.enc.00000 HASH 549',
            'init',
        ]
        assert index() == [
            ('./bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
            ('./link.txt', 'symlink', './bar.txt', '0', '-'),
        ]
        ##
        sh.run('mkdir dir')
        sh.run('cd dir && ln -s ../bar.txt link.txt')
        sh.run('backup-add')
        assert diff() == [
            ('addition:', './dir/link.txt', 'symlink', './bar.txt', '0', '-'),
        ]
        assert additions() == [
            ('./dir/link.txt', 'symlink', './bar.txt', '0', '-'),
        ]
        sh.run('backup-commit')
        assert log() == [
            'index-only-update',
            '0000000000.DATE.tar.lz4.enc.00000 HASH 549',
            'init',
        ]
        assert index() == [
            ('./bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
            ('./dir/link.txt', 'symlink', './bar.txt', '0', '-'),
            ('./link.txt', 'symlink', './bar.txt', '0', '-'),
        ]
        ##
        with sh.tempdir():
            os.environ['BACKUP_ROOT'] = os.getcwd()
            _ = find('.') # clone the repo with the first call to find()
            assert [find('.', commit) for commit in commits()] == [
                [
                    ('./bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
                    ('./dir/link.txt', 'symlink', './bar.txt', '0', '-'),
                    ('./link.txt', 'symlink', './bar.txt', '0', '-'),
                ],
                [
                    ('./bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
                    ('./link.txt', 'symlink', './bar.txt', '0', '-'),
                ],
                [],
            ]
        ##
        with sh.tempdir():
            os.environ['BACKUP_ROOT'] = os.getcwd()
            restore('.')
            assert sh.run(r'find -printf "%y %p %l\n" | grep -v "\./\.backup" | grep -E "^(l|f)"').splitlines() == [
                'f ./bar.txt',
                'l ./dir/link.txt ../bar.txt',
                'l ./link.txt bar.txt',
            ]
            assert sh.run('cat link.txt') == 'foo'
            assert sh.run('cat dir/link.txt') == 'foo'
            assert sh.run('cat bar.txt') == 'foo'

def test_executable():
    with sh.tempdir():
        uid = str(uuid.uuid4())
        os.environ['BACKUP_GIT'] = os.environ['BACKUP_TEST_GIT']
        os.environ['BACKUP_S3'] = os.environ['BACKUP_TEST_S3']
        os.environ['BACKUP_CHUNK_MEGABYTES'] = '100'
        os.environ['BACKUP_ROOT'] = os.getcwd()
        sh.run('libaws s3-rm', os.environ['BACKUP_S3'].split('s3://')[-1].split('/')[0] + '/', '-r')
        sh.run('libaws dynamodb-item-rm-all', os.environ['BACKUP_GIT'].split('+')[-1].split('/')[0], 'id')
        for k, v in os.environ.items():
            if k.startswith('BACKUP_'):
                print(k, '=>', v)
        ##
        sh.run('echo foo > bar.txt')
        sh.run('chmod +x bar.txt')
        sh.run('backup-add')
        assert diff() == [
            ('addition:', './bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '755'),
        ]
        assert additions() == [
            ('./bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '755'),
        ]
        sh.run('backup-commit')
        assert log() == [
            '0000000000.DATE.tar.lz4.enc.00000 HASH 549',
            'init',
        ]
        assert index() == [
            ('./bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '755'),
        ]
        ##
        sh.run('mkdir dir')
        sh.run('cd dir && ln -s ../bar.txt link.txt')
        sh.run('backup-add')
        assert diff() == [
            ('addition:', './dir/link.txt', 'symlink', './bar.txt', '0', '-'),
        ]
        assert additions() == [
            ('./dir/link.txt', 'symlink', './bar.txt', '0', '-'),
        ]
        sh.run('backup-commit')
        assert log() == [
            'index-only-update',
            '0000000000.DATE.tar.lz4.enc.00000 HASH 549',
            'init',
        ]
        assert index() == [
            ('./bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '755'),
            ('./dir/link.txt', 'symlink', './bar.txt', '0', '-'),
        ]
        ##
        with sh.tempdir():
            os.environ['BACKUP_ROOT'] = os.getcwd()
            _ = find('.') # clone the repo with the first call to find()
            assert [find('.', commit) for commit in commits()] == [
                [
                    ('./bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '755'),
                    ('./dir/link.txt', 'symlink', './bar.txt', '0', '-'),
                ],
                [
                    ('./bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '755'),
                ],
                [],
            ]
        ##
        with sh.tempdir():
            os.environ['BACKUP_ROOT'] = os.getcwd()
            restore('.')
            assert sh.run(r'find -printf "%y %p %l\n" | grep -v "\./\.backup" | grep -P "^(l|f)"').splitlines() == [
                'f ./bar.txt',
                'l ./dir/link.txt ../bar.txt',
            ]
            assert sh.run('cat dir/link.txt') == 'foo'
            assert sh.run('cat bar.txt') == 'foo'
            assert os.stat('bar.txt').st_mode == int('0o100755', 8)

def test_symlink_directory():
    with sh.tempdir():
        uid = str(uuid.uuid4())
        os.environ['BACKUP_GIT'] = os.environ['BACKUP_TEST_GIT']
        os.environ['BACKUP_S3'] = os.environ['BACKUP_TEST_S3']
        os.environ['BACKUP_CHUNK_MEGABYTES'] = '100'
        os.environ['BACKUP_ROOT'] = os.getcwd()
        sh.run('libaws s3-rm', os.environ['BACKUP_S3'].split('s3://')[-1].split('/')[0] + '/', '-r')
        sh.run('libaws dynamodb-item-rm-all', os.environ['BACKUP_GIT'].split('+')[-1].split('/')[0], 'id')
        for k, v in os.environ.items():
            if k.startswith('BACKUP_'):
                print(k, '=>', v)
        ##
        sh.run('mkdir dir1')
        sh.run('echo foo > dir1/bar.txt')
        sh.run('ln -ns dir1 link1')
        sh.run('backup-add')
        assert diff() == [
            ('addition:', './dir1/bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
            ('addition:', './link1', 'symlink', './dir1', '0', '-'),
        ]
        assert additions() == [
            ('./dir1/bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
            ('./link1', 'symlink', './dir1', '0', '-'),
        ]
        sh.run('backup-commit')
        assert log() == [
            '0000000000.DATE.tar.lz4.enc.00000 HASH 549',
            'init',
        ]
        assert index() == [
            ('./dir1/bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
            ('./link1', 'symlink', './dir1', '0', '-'),
        ]
        ##
        with sh.tempdir():
            os.environ['BACKUP_ROOT'] = os.getcwd()
            _ = find('.') # clone the repo with the first call to find()
            assert [find('.', commit) for commit in commits() if find('.', commit)] == [
                [
                    ('./dir1/bar.txt', '0000000000.DATE.tar.lz4.enc.00000', 'd202d795', '4', '644'),
                    ('./link1', 'symlink', './dir1', '0', '-'),
                ],
            ]
        ##
        with sh.tempdir():
            os.environ['BACKUP_ROOT'] = os.getcwd()
            restore('.')
            assert sh.run(r'find -printf "%y %p %l\n" | grep -v "\./\.backup" | grep -E "^(l|f)"').splitlines() == [
                'f ./dir1/bar.txt',
                'l ./link1 dir1',
            ]
            assert sh.run('cat link1/bar.txt') == 'foo'
            assert sh.run('cat dir1/bar.txt') == 'foo'
