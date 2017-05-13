import subprocess
ans = '[  PASSED  ] 15 tests.'
cnt = 0
while True:
	cnt += 1
	cont = subprocess.check_output(['make test_part2'], shell=True)
	b = cont.split('\n')[-2]
	print b, cnt
	if b != ans:
		with open('testres', 'w') as f:
			f.write(cont)
		break
