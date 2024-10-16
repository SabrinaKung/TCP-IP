all:
	go build -o vhost cmd/vhost/vhost.go
	go build -o vrouter cmd/vrouter/vrouter.go

clean:
	rm vhost vrouter