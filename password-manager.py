#!/usr/bin/python

def validate_password(m_pass):
	real_m_pass_file = open('passwords/master_password', 'r')
	real_m_pass = real_m_pass_file.readline()
	real_m_pass_file.close()
	if m_pass != real_m_pass:
		print 'Incorrect password'
		exit(0)

	print 'Correct password!'

m_pass = raw_input('Master password: ')
validate_password(m_pass)