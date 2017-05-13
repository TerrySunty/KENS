import subprocess
ans = '[  PASSED  ] 12 tests.'
cnt = 0
while True:
	cnt += 1
	cont = subprocess.check_output(['make test_part3'], shell=True)
	b = cont.split('\n')[-2]
	print b, cnt
	if b != ans:
		with open('testres', 'w') as f:
			f.write(cont)
		break
