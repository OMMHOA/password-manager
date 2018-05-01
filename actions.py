from cryptotools.readers import PasswordReader, DbReader
from cryptotools.writers import PasswordWriter, PasswordGenerator, clear


def _add(args, m_pass):
    print('add called')
    PasswordWriter(args.domain, args.username).write_pass(m_pass)


def _generate(args, m_pass):
    print('generate called')
    PasswordGenerator(args.domain, args.username, args.difficulty, args.length).write_pass(m_pass)


def _get(args, m_pass):
    print('get called')
    PasswordReader(args.domain, args.username).read(m_pass)


def _list(args, m_pass):
    print('list called')
    DbReader().read(m_pass)


def _clear(args, m_pass):
    print('clear called')
    clear()


actions = {
    'add': _add,
    'generate': _generate,
    'get': _get,
    'list': _list,
    'clear': _clear
}
