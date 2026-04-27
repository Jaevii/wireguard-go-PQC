PREFIX ?= /usr
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin

OQS_DIR         ?= vendor/liboqs
OQS_BUILD_DIR   ?= $(OQS_DIR)/build
OQS_PREFIX      ?= $(CURDIR)/.deps/liboqs
OQS_PKGCONFIG_DIR := $(OQS_PREFIX)/lib/pkgconfig
OQS_LIBGO_PC    := $(OQS_PKGCONFIG_DIR)/liboqs-go.pc
OQS_PKGCONFIG_ENV := PKG_CONFIG_PATH="$(OQS_PKGCONFIG_DIR):$${PKG_CONFIG_PATH}"

export GO111MODULE := on
MAKEFLAGS += --no-print-directory

# ── Top-level target ────────────────────────────────────────────────────────
all: generate-version-and-build

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	    tag="$$(git describe --dirty 2>/dev/null)" && \
	    ver="$$(printf 'package main\n\nconst Version = "%s"\n' "$$tag")" && \
	    [ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	    echo "$$ver" > version.go && \
	    git update-index --assume-unchanged version.go || true
	@$(MAKE) wireguard-go

# ── liboqs submodule ────────────────────────────────────────────────────────
$(OQS_DIR)/CMakeLists.txt:
	git submodule update --init --recursive $(OQS_DIR)

$(OQS_BUILD_DIR)/CMakeCache.txt: $(OQS_DIR)/CMakeLists.txt
	mkdir -p "$(OQS_BUILD_DIR)"
	cmake -S "$(OQS_DIR)" -B "$(OQS_BUILD_DIR)" -G Ninja \
	    -DCMAKE_BUILD_TYPE=Release \
	    -DCMAKE_INSTALL_PREFIX="$(OQS_PREFIX)" \
	    -DBUILD_SHARED_LIBS=OFF \
	    -DOQS_BUILD_ONLY_LIB=ON \
	    -DOQS_USE_OPENSSL=OFF \
	    -DOQS_ENABLE_KEM_BIKE=OFF \
	    -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=OFF \
	    -DOQS_ENABLE_KEM_FRODOKEM=OFF \
	    -DOQS_ENABLE_KEM_HQC=ON \
	    -DOQS_ENABLE_KEM_KYBER=OFF \
	    -DOQS_ENABLE_KEM_ML_KEM=ON \
	    -DOQS_ENABLE_KEM_NTRU=OFF \
	    -DOQS_ENABLE_KEM_NTRUPRIME=OFF \
	    -DOQS_ENABLE_SIG_DILITHIUM=OFF \
	    -DOQS_ENABLE_SIG_FALCON=OFF \
	    -DOQS_ENABLE_SIG_SPHINCS=OFF \
	    -DOQS_ENABLE_SIG_ML_DSA=OFF

$(OQS_PREFIX)/include/oqs/oqs.h: $(OQS_BUILD_DIR)/CMakeCache.txt
	cmake --build "$(OQS_BUILD_DIR)"
	cmake --install "$(OQS_BUILD_DIR)"

# ── liboqs-go pkg-config shim ───────────────────────────────────────────────
# liboqs-go expects a liboqs-go.pc file. We generate one that points
# at our local install prefix rather than relying on a fragile symlink.
$(OQS_LIBGO_PC): $(OQS_PREFIX)/include/oqs/oqs.h
	mkdir -p "$(OQS_PKGCONFIG_DIR)"
	cp "$(OQS_PKGCONFIG_DIR)/liboqs.pc" "$(OQS_LIBGO_PC)"

oqs: $(OQS_LIBGO_PC)

# ── wireguard-go binary ─────────────────────────────────────────────────────
wireguard-go: oqs $(wildcard *.go) $(wildcard */*.go)
	$(OQS_PKGCONFIG_ENV) go build -v -o "$@"

# ── install ─────────────────────────────────────────────────────────────────
install: wireguard-go
	install -v -d "$(DESTDIR)$(BINDIR)"
	install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/wireguard-go"

# ── test ────────────────────────────────────────────────────────────────────
test: oqs
	$(OQS_PKGCONFIG_ENV) go test ./...

# ── clean ───────────────────────────────────────────────────────────────────
clean:
	rm -f wireguard-go

clean-oqs:
	rm -rf "$(OQS_BUILD_DIR)" "$(OQS_PREFIX)"

.PHONY: all clean clean-oqs oqs test install generate-version-and-build