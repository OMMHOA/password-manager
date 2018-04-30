from crypto_utils import PasswordWriter, PasswordGenerator, PasswordReader


def _add(args, m_pass):
    print('add called')
    writer = PasswordWriter(args.domain, args.username)
    writer.write_pass(m_pass)


def _generate(args, m_pass):
    print('generate called')
    writer = PasswordGenerator(args.domain, args.username, args.difficulty, args.length)
    writer.write_pass(m_pass)


def _get(args, m_pass):
    print('get called')
    reader = PasswordReader(args.domain, args.username)
    reader.read_pass(m_pass)


def _list(args, m_pass):
    print('list called')
    pass


actions = {
    'add': _add,
    'generate': _generate,
    'get': _get,
    'list': _list
}
