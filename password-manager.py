#!/usr/bin/python

from getpass import getpass

def validate_password(m_pass):
	real_m_pass_file = open('passwords/master_password', 'r')
	real_m_pass = real_m_pass_file.readline()
	real_m_pass_file.close()
	if m_pass == real_m_pass:
		print('Correct password!')
		return
	print('Incorrect password!')
	exit(0)

m_pass = getpass('Master password: ')
validate_password(m_pass)
