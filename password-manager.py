#!/usr/bin/env python3

from argparse import ArgumentParser
from getpass import getpass
from actions import actions
from sys import exit, argv
from os import path, mkdir


def add_account_info_to_parser(parser):
    parser.add_argument('domain')
    parser.add_argument('username')


parser = ArgumentParser(prog='Password Manager')
subparsers = parser.add_subparsers()

password_parser = subparsers.add_parser('add')
add_account_info_to_parser(password_parser)

generate_parser = subparsers.add_parser('generate')
add_account_info_to_parser(generate_parser)
generate_parser.add_argument('-x', '--difficulty', metavar='DIFFICULTY', type=int, required=True,
                             choices=[1, 2, 3], help='Set password difficulty. ' +
                                                     'Can be 1-[a-zA-Z], 2-[a-zA-Z0-9],3-[a-zA-Z0-9]')
generate_parser.add_argument('-l', '--length', metavar='LENGTH', type=int, required=True,
                             help='Set password length.')

get_parser = subparsers.add_parser('get')
add_account_info_to_parser(get_parser)

subparsers.add_parser('list')
subparsers.add_parser('clear')


def main():
    args = argv[1:]
    master_password = get_master_password()

    if not path.isdir('passwords'):
        mkdir('passwords')

    if len(args) > 0:
        execute_command(args, master_password)
    else:
        shell_mode(master_password)


def get_master_password():
    master_password = ''
    while master_password == '':
        master_password = getpass('Master password: ')

    return master_password


def execute_command(args, master_password):
    try:
        command_args = parser.parse_args(args)
        print(command_args)
        command = args[0]
        actions[command](command_args, master_password)
    except SystemExit:
        print('Try again ;)')


def shell_mode(master_password):
    print('You entered the shell. Write exit or press ctrl+C to exit!')
    while True:
        command = input('> ')
        handle_exit(command)
        if command == '':
            continue
        command = command.split()
        execute_command(command, master_password)


def handle_exit(command):
    if command == 'exit':
        print('Bye!')
        exit(0)


main()
