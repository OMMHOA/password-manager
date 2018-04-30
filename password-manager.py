#!/usr/bin/env python3

from getpass import getpass
import argparse, sys

# def get_parser():
# 	# basic arguments
# 	parser = argparse.ArgumentParser(prog='Password Manager')
# 	parser.add_argument('domain', nargs='?')
# 	parser.add_argument('username', nargs='?')
# 	subparsers = parser.add_subparsers()

# 	# subcommands
# 	password_parser = subparsers.add_parser('add-pass')
# 	password_parser.add_argument('-p', '-pass', metavar='PASSWORD', help='Use predefined password.',
# 		required=True)

# 	generate_parser = subparsers.add_parser('generate-pass')
# 	generate_parser.add_argument('-x', metavar='DIFFICULTY', type=int, help='Set password difficulty. ' + 
# 		'Can be 1-[a-zA-Z], 2-[a-zA-Z0-9],3-[a-zA-Z0-9]+special characters', required=True)
# 	generate_parser.add_argument('-l', metavar='LENGTH', help='Set password length.', required=True)

# 	return parser

def validate_password(m_pass):
	real_m_pass_file = open('passwords/master_password', 'r')
	real_m_pass = real_m_pass_file.readline()
	real_m_pass_file.close()
	if m_pass == real_m_pass:
		print('Correct password!')
		return
	print('Incorrect password!')
	exit(0)

def exit(command):
	print('Goodbye!')
	sys.exit(0)

def add(command):
	print('add called')

def print_wrong_command(command):
	print('Unrecognized command: %s' % command)

actions = {
	'exit' : exit,
	'add' : add
}

m_pass = getpass('Master password: ')
validate_password(m_pass)

while True:
	command = input()
	actions.get(command, print_wrong_command)(command)

