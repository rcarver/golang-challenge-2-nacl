verify: vet test test_echo

golang-challenge-2-nacl: *.go
	go build .

build: golang-challenge-2-nacl

server: golang-challenge-2-nacl
	./golang-challenge-2-nacl -l 8080

kill: 
	killall golang-challenge-2-nacl

client: golang-challenge-2-nacl
	./golang-challenge-2-nacl 8080 foo

test_echo: golang-challenge-2-nacl
	./golang-challenge-2-nacl -l 8080 &
	./golang-challenge-2-nacl 8080 "hello world"
	killall golang-challenge-2-nacl

test:
	go test .

vet:
	go fmt .
	go vet .
	$$GOPATH/bin/golint .

.PHONY: build server client test_echo vet verify

gc2: 
	rm -rf $@
	mkdir -p $@
	cp *.go $@

gc2.zip: gc2
	zip -r $@ $^

dist: verify clean_dist gc2.zip

clean_dist:
	rm -rf gc2
	rm -f gc2.zip

.PHONY: clean_dist dist
