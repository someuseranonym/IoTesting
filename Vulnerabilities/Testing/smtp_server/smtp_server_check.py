import smtplib
s = smtplib.SMTP('localhost', 25)
print(s.verify('admin'))  # Должен вернуть (250, b'admin exists')
print(s.verify('nonexistent'))  # Должен вернуть (550, b'User unknown')