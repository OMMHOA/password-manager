#!/usr/bin/python

def validate_password(m_pass):
	real_m_pass_file = open('passwords/master_password', 'r')
	real_m_pass = real_m_pass_file.readline()
	real_m_pass_file.close()
	if m_pass == real_m_pass:
		print('Correct password!')
		exit(0)

	print('Incorrect password')

m_pass = input('Master password: ')
validate_password(m_pass)
