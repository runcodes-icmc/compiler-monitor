# Compilation image
FROM debian:bullseye-slim as builder

# Update system
RUN apt-get update
RUN apt-get update && apt-get upgrade -y

# Install build tools
RUN apt-get install -y build-essential cmake libboost-all-dev pkg-config ninja-build

# Create build directory
RUN mkdir /build
WORKDIR /build
COPY ./CMakeLists.txt ./CMakeLists.txt
COPY ./src/ ./src/

# Build project
RUN cmake .
RUN cmake --build .

# Create final image with only the built binary
FROM debian:bullseye-slim as dist
COPY --from=builder /build/monitor /usr/bin/monitor