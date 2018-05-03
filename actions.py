from cryptotools.readers import PasswordReader, List
from cryptotools.writers import PasswordWriter, PasswordGenerator, PasswordDeleter, clear


def _add(args, m_pass):
    # print('add called')
    PasswordWriter(args.domain, args.username).write_pass(m_pass)


def _generate(args, m_pass):
    # print('generate called')
    PasswordGenerator(args.domain, args.username, args.difficulty, args.length).write_pass(m_pass)


def _get(args, m_pass):
    # print('get called')
    PasswordReader(args.domain, args.username).read(m_pass)


def _list(args, m_pass):
    # print('list called')
    List().read(m_pass)


def _clear(args, m_pass):
    # print('clear called')
    clear()


def _delete(args, m_pass):
    # print('delete called')
    PasswordDeleter(args.domain, args.username).delete()


actions = {
    'add': _add,
    'generate': _generate,
    'get': _get,
    'list': _list,
    'clear': _clear,
    'delete': _delete
}
