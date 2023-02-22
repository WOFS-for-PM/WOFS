all: clean rw_test

rw_test:
	mkdir -p ./bin
	gcc rw_test.c -o ./bin/rw_test -O3 --static

clean:
	rm -f ./bin/rw_test

	