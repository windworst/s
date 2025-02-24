# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=s
BINARY_UNIX=$(BINARY_NAME)
MAIN_PATH=cmd/scanner/main.go

# 根据操作系统设置二进制文件名
ifeq ($(OS),Windows_NT)
    BINARY=$(BINARY_NAME).exe
else
    BINARY=$(BINARY_NAME)
endif

all: test build

build:
	$(GOBUILD) -o $(BINARY) $(MAIN_PATH)

test:
	$(GOTEST) -v ./...

clean:
	$(GOCLEAN)
	rm -f $(BINARY)
	rm -f $(BINARY_UNIX)

run:
	$(GOBUILD) -o $(BINARY) $(MAIN_PATH)
	./$(BINARY)

deps:
	$(GOMOD) tidy

# 交叉编译
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) $(MAIN_PATH)

build-mac:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BINARY_UNIX) $(MAIN_PATH)

build-mac-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BINARY_UNIX) $(MAIN_PATH)

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME).exe $(MAIN_PATH)

# 安装到系统
install: build
	mv $(BINARY) /usr/local/bin/

# 从系统中卸载
uninstall:
	rm -f /usr/local/bin/$(BINARY_NAME)

.PHONY: all build test clean run deps build-linux build-mac build-mac-arm64 build-windows install uninstall