Web application firewall used by Azure Application Gateway.

If you are using this repo as a submodule of Networking-AppGw, then you can
simply use the AppGw dev container. Else, if you want to run this repo
standalone, then use the following commands for container management:
```
# Automatically build and run the dev container
docker-compose run --rm --service-ports --name azwafdev azwafdev

# If you get errors about an existing container with the same name, delete existing containers first
docker container prune -f
docker network prune -f

# To force rebuild of container image
docker-compose build --no-cache azwafdev
```

Within the container you can run the following commands:
```
# To run main function
go run azwaf/cmd/server

# To run all tests
go test azwaf/...

# To run code style analysis
go install golang.org/x/lint/golint
golint ./...

# To wait for a remote debugger to attach and debug tests
dlv test --api-version=2 --headless --listen=:2345 "azwaf/somepackage" -- -test.run TestSomeFunction

# To wait for a remote debugger to attach to the main function
dlv debug --api-version=2 --headless --listen=:2345 "azwaf/cmd/server"

# To regenerate the gRPC stubs
protoc -I./proto/ waf.proto --go_out=plugins=grpc:proto
protoc -I./proto/ config.proto --go_out=plugins=grpc:proto
```
