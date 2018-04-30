#!/usr/bin/env python3

import argparse
import sys
from getpass import getpass
from crypto_utils import PasswordWriter, PasswordGenerator, PasswordReader


def main():
    args = parse_args()
    master_password = getpass('Master password: ')

    if len(args) > 0:
        handle_args(args)
    else:
        shell_mode(master_password)


def parse_args():
    parser = get_parser()
    args = parser.parse_args()
    return vars(args)


def get_parser():
    # basic arguments
    parser = argparse.ArgumentParser(prog='Password Manager')
    subparsers = parser.add_subparsers()

    # subcommands
    password_parser = subparsers.add_parser('add')
    add_account_info_to_parser(password_parser)

    generate_parser = subparsers.add_parser('generate')
    add_account_info_to_parser(generate_parser)
    generate_parser.add_argument('-x', '--difficulty', metavar='DIFFICULTY', type=int, required=True,
                                 choices=[1, 2, 3], help='Set password difficulty. ' +
                                                         'Can be 1-[a-zA-Z], 2-[a-zA-Z0-9],3-[a-zA-Z0-9]')
    generate_parser.add_argument('-l', '--length', metavar='LENGTH', type=int, required=True,
                                 help='Set password length.')

    return parser


def add_account_info_to_parser(parser):
    parser.add_argument('DOMAIN')
    parser.add_argument('USERNAME')


def handle_args(args):
    print('There are some args')


def parse_command(cmd):
    parser = get_parser()
    split_command = cmd.split(' ')
    args = parser.parse_args(split_command)
    return vars(args)


def exit(command, m_pass):
    print('Goodbye!')
    sys.exit(0)


def add(command, m_pass):
    print('add called')
    writer = PasswordWriter('facebook', 'user', 'dummyPass')
    writer.write_pass(m_pass)


def generate(command, m_pass):
    print('generate called')
    writer = PasswordGenerator('facebook', 'user', 3, 8)
    writer.write_pass(m_pass)


def get(command, m_pass):
    print('get called')
    reader = PasswordReader('facebook', 'user')
    reader.read_pass(m_pass)


def print_wrong_command(wrong_command, m_pass):
    print('Unrecognized command: %s' % wrong_command)


actions = {
    'exit': exit,
    'add': add,
    'generate': generate,
    'get': get
}


def shell_mode(master_password):
    print('You entered the shell. Write exit or press ctrl+C to exit!')
    while True:
        command = input()
        actions.get(command, print_wrong_command)(command, master_password)


main()
