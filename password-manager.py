#!/usr/bin/env python3

from getpass import getpass
import argparse

def validate_password(m_pass):
	real_m_pass_file = open('passwords/master_password', 'r')
	real_m_pass = real_m_pass_file.readline()
	real_m_pass_file.close()
	if m_pass == real_m_pass:
		print('Correct password!')
		return
	print('Incorrect password!')
	exit(0)

parser = argparse.ArgumentParser()
parser.add_argument('-pass', help='')
parser.parse_args()

m_pass = getpass('Master password: ')
validate_password(m_pass)

while True:
	command = input()
	if command == 'exit':
		break
	print(command)

print('Goodbye!')