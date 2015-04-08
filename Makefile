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

rcarver:
	rm -rf $@
	mkdir -p $@
	cp *.go $@

rcarver.zip: rcarver
	zip -r $@ $^

dist: clean_dist rcarver.zip

clean_dist:
	rm -rf rcarver
	rm rcarver.zip

.PHONY: clean_dist dist
