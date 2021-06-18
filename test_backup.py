import shell as sh
import os
import re
import uuid

sh.set['stream'] = True

def scrub(text):
    text = re.sub(r'\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}Z', 'DATE', text) # remove digits from date
    text = re.sub(r'(\w{8})\w{120}', r'\1', text) # truncate blake2b
    return text

def scrub2(text):
    text = re.sub(r'\d{4}\-\d{2}\-\d{2}T\d{2}:\d{2}:\d{2}Z', 'DATE', text) # remove digits from date
    text = re.sub(r'\w{128}', 'HASH', text) # remove blake2b
    return text

def diff():
    return [(kind, path, tar, blake2b, size) for x in scrub(sh.run('backup-diff')).splitlines() for kind, path, tar, blake2b, size in [x.split()]]

def additions():
    return [(path, tar, blake2b, size) for x in scrub(sh.run('backup-additions')).splitlines() for path, tar, blake2b, size in [x.split()]]

def log():
    return scrub2(sh.run('backup-log --pretty=%s index')).splitlines()

def commits():
    return sh.run('backup-log --pretty=%H index').splitlines()

def index():
    return [(path, tar, blake2b, size) for x in scrub(sh.run('backup-index')).splitlines() for path, tar, blake2b, size in [x.split()]]

def find(regex, revision='HEAD'):
    return [(path, tar, blake2b, size) for x in scrub(sh.run(f"backup-find '{regex}' {revision}")).splitlines() for path, tar, blake2b, size in [x.split()]]

def restore(regex, revision='HEAD'):
    return [(path, blake2b[:8]) for x in sh.run(f"backup-restore '{regex}' {revision}").splitlines() for path, blake2b in [x.split()]]

def test1():

    with sh.tempdir():

        uid = str(uuid.uuid4())
        os.environ['BACKUP_RCLONE_REMOTE'] = os.environ['BACKUP_TEST_RCLONE_REMOTE']
        os.environ['BACKUP_DESTINATION'] = os.environ['BACKUP_TEST_DESTINATION'] + '/' + uid
        os.environ['BACKUP_STORAGE_CLASS'] = 'STANDARD_IA'
        os.environ['BACKUP_CHUNK_MEGABYTES'] = '100'
        os.environ['BACKUP_ROOT'] = os.getcwd()
        for k, v in os.environ.items():
            if k.startswith('BACKUP_'):
                print(k, '=>', v)

        sh.run('echo foo > bar.txt')
        sh.run('backup-add')
        assert diff() == [
            ('addition:', './bar.txt', '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
        ]
        assert additions() == [
            ('./bar.txt', '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
        ]
        sh.run('backup-commit')
        assert log() == [
            '0000000000.DATE.tar.lz4.gpg.00000 HASH 1510',
            'init',
        ]
        assert index() == [
            ('./bar.txt', '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
        ]

        sh.run('echo foo > bar2.txt')
        sh.run('backup-add')
        assert diff() == [
            ('addition:', './bar2.txt', '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
        ]
        assert additions() == [
            ('./bar2.txt', '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
        ]
        sh.run('backup-commit')
        assert log() == [
            'index-only-update',
            '0000000000.DATE.tar.lz4.gpg.00000 HASH 1510',
            'init',
        ]
        assert index() == [
            ('./bar.txt',  '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
            ('./bar2.txt', '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
        ]

        sh.run('echo asdf > asdf.txt')
        sh.run('backup-add')
        assert diff() == [
            ('addition:', './asdf.txt', '0000000001.DATE.tar.lz4.gpg.00000', '36b807d5', '5')
        ]
        assert additions() == [
            ('./asdf.txt', '0000000001.DATE.tar.lz4.gpg.00000', '36b807d5', '5')
        ]
        sh.run('backup-commit')
        assert log() == [
            '0000000001.DATE.tar.lz4.gpg.00000 HASH 1513',
            'index-only-update',
            '0000000000.DATE.tar.lz4.gpg.00000 HASH 1510',
            'init',
        ]
        assert index() == [
            ('./asdf.txt', '0000000001.DATE.tar.lz4.gpg.00000', '36b807d5', '5'),
            ('./bar.txt',  '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
            ('./bar2.txt', '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
        ]

        with sh.tempdir():
            os.environ['BACKUP_ROOT'] = os.getcwd()
            _ = find('.') # clone the repo with the first call to find()
            assert [find('.', commit) for commit in commits()] == [find(r'\.txt$', commit) for commit in commits()] == [
                [
                    ('./asdf.txt', '0000000001.DATE.tar.lz4.gpg.00000', '36b807d5', '5'),
                    ('./bar.txt',  '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
                    ('./bar2.txt', '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
                ],
                [
                    ('./bar.txt',  '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
                    ('./bar2.txt', '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
                ],
                [
                    ('./bar.txt',  '0000000000.DATE.tar.lz4.gpg.00000', 'd202d795', '4'),
                ],
                [],
            ]
            assert [find('.*asdf.*', commit) for commit in commits()] == [
                [
                    ('./asdf.txt', '0000000001.DATE.tar.lz4.gpg.00000', '36b807d5', '5'),
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
