FROM ubuntu:16.04

SHELL ["/bin/bash", "-c"]

# Install dependencies from apt and then tidy up cache
RUN apt-get update && \
    apt-get install -y vim curl wget git build-essential pkg-config unzip && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

# Install Go
RUN curl -L -o /tmp/go.tar.gz https://dl.google.com/go/go1.11.4.linux-amd64.tar.gz && \
    tar -xzf /tmp/go.tar.gz -C /usr/local && \
    rm /tmp/go.tar.gz
ENV PATH=${PATH}:/usr/local/go/bin:/root/go/bin

# Install a few Go dependencies
RUN go get -u github.com/derekparker/delve/cmd/dlv && \
    go get -u github.com/golang/protobuf/protoc-gen-go && \
    git -C /root/go/src/github.com/golang/protobuf/protoc-gen-go checkout v1.2.0 && \
    go install github.com/golang/protobuf/protoc-gen-go

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
