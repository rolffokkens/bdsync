f = open('srcfile2k', 'wb')

f.write(b'\0' * (1024 * 2))
f.seek(1023)
f.write(b'\x80')
