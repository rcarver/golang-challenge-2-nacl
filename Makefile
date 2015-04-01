golang-challenge-2-nacl: *.go
	go build .

build: golang-challenge-2-nacl

server: golang-challenge-2-nacl
	./golang-challenge-2-nacl -l 8080

client: golang-challenge-2-nacl
	./golang-challenge-2-nacl 8080 foo

test_echo: golang-challenge-2-nacl
	./golang-challenge-2-nacl -l 8080 &
	./golang-challenge-2-nacl 8080 "hello world"

.PHONY: build server client test_echo
