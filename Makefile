# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOVERS=$(GOCMD) version
BINARY_NAME=heartbleed

all: build
build:
	$(GOBUILD) -o $(BINARY_NAME) -v
clean:
	rm -f $(BINARY_NAME)
install: # install Go to local machine, may or may not work.
	curl -OL https://go.dev/dl/go1.20.2.linux-amd64.tar.gz
	sudo tar -C /usr/local -xzf go1.20.2.linux-amd64.tar.gz
	echo 'export PATH=$PATH:/usr/local/go/bin' >> $HOME/.profile
	source $HOME/.profile
	$(GOVERS)
