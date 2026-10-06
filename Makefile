PREFIX ?= $(HOME)/.local
BINARY := ssh-btoim
CARGO ?= cargo
# Absolute repository path, so `make -f /path/to/Makefile` works from any
# directory and a relative PREFIX is taken relative to where make was run.
REPO := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

.PHONY: all build install test e2e clean

all: build

build:
	cd "$(REPO)" && $(CARGO) build --release --locked

# Builds, then installs PREFIX/libexec/ssh-btoim/ssh-btoim-<UTC time>-<pid>
# behind the atomically switched symlink PREFIX/bin/ssh-btoim.
install:
	"$(REPO)/scripts/install.sh" "$(PREFIX)/bin/$(BINARY)"

test:
	cd "$(REPO)" && $(CARGO) test --locked
	"$(REPO)/scripts/test_darwin_install_signature.sh"

e2e:
	cd "$(REPO)" && $(CARGO) build --locked && tests/e2e.sh

clean:
	cd "$(REPO)" && $(CARGO) clean
