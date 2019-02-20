Web application firewall used by Azure Application Gateway.

Container management:
```
# Automatically build and run the dev container
docker-compose run --rm --service-ports --name azwafdev dev

# If you get errors about an existing container with the same name, delete existing containers first
docker container prune -f
docker network prune -f

# To force rebuild of container image
docker-compose build --no-cache dev
```

Within the container you can run the following commands:
```
# To run main function
go run .

# To run all tests
go test ./... -v

# To wait for a remote debugger to attach and debug tests
dlv test --api-version=2 --headless --listen=:2345 "azwaf/somepackage" -- -test.v

# To wait for a remote debugger to attach to the main function
dlv debug --api-version=2 --headless --listen=:2345

# To regenerate the gRPC stubs
protoc -I./proto/ waf.proto --go_out=plugins=grpc:proto
```
