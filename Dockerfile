FROM ubuntu:16.04

SHELL ["/bin/bash", "-c"]

# Install dependencies from apt and then tidy up cache
RUN apt-get update && \
    apt-get install -y vim curl wget git build-essential pkg-config unzip libgoogle-perftools-dev libboost-all-dev ragel && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Install Go
RUN curl -L -o /tmp/go.tar.gz https://dl.google.com/go/go1.13.3.linux-amd64.tar.gz && \
    tar -xzf /tmp/go.tar.gz -C /usr/local && \
    rm /tmp/go.tar.gz
ENV PATH=${PATH}:/usr/local/go/bin:/root/go/bin

# Install Go tools
RUN GO111MODULE=on go get -v golang.org/x/tools/gopls@latest 2>&1 \
&& GO111MODULE=on go get -v \
        honnef.co/go/tools/...@latest \
        golang.org/x/tools/cmd/gorename@latest \
        golang.org/x/tools/cmd/goimports@latest \
        golang.org/x/tools/cmd/guru@latest \
        golang.org/x/lint/golint@latest \
        github.com/mdempsky/gocode@latest \
        github.com/cweill/gotests/...@latest \
        github.com/haya14busa/goplay/cmd/goplay@latest \
        github.com/sqs/goreturns@latest \
        github.com/josharian/impl@latest \
        github.com/davidrjenni/reftools/cmd/fillstruct@latest \
        github.com/ramya-rao-a/go-outline@latest  \
        github.com/acroca/go-symbols@latest  \
        github.com/godoctor/godoctor@latest  \
        github.com/rogpeppe/godef@latest  \
        github.com/zmb3/gogetdoc@latest \
        github.com/fatih/gomodifytags@latest  \
        github.com/mgechev/revive@latest  \
        github.com/go-delve/delve/cmd/dlv@latest \
        github.com/golang/protobuf/protoc-gen-go@v1.2.0 2>&1


# Install protoc
RUN curl -L -o /tmp/protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v3.6.1/protoc-3.6.1-linux-x86_64.zip && \
    unzip /tmp/protoc.zip -d /tmp/protoc && \
    mv /tmp/protoc/bin/protoc /usr/local/bin/ && \
    rm -fr /tmp/protoc

# Install Hyperscan
RUN cd /tmp && \
    HYPERSCAN_PKG_FILENAME=azwaf-libhyperscan_5.1.1.2.deb && \
    wget -q https://azwafdependencies.blob.core.windows.net/ubuntu/$HYPERSCAN_PKG_FILENAME && \
    dpkg --install $HYPERSCAN_PKG_FILENAME && \
    rm $HYPERSCAN_PKG_FILENAME
