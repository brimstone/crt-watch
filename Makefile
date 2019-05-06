crt-watch: *.go Makefile
	go build -v

.PHONY: test
test: crt-watch
	./crt-watch github.com

.PHONY: watch
watch:
	find *.go Makefile | entr -c make test
