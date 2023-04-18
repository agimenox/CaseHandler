#test

from datetime import date

datenow = date.today()
print(f'{datenow}')

start = date(2023, 2, 5)
end = date(2023, 2, 18)

if start <= datenow <= end:
    print('correcto')
else:
    print('No correcto')