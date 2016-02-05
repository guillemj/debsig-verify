FROM debian:buster

WORKDIR /build

# We need this file for the apt build-dep command.
COPY debian/ /build/debian/

# We need the dependencies for the travis script, and build-essential,
# and then the build-dependencies for the package.
RUN apt update -qq \
    && apt install --no-install-recommends -y \
      git wget curl ruby \
    && apt build-dep -y .
