# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../../config.mk

CFLAGS=$(shell pkg-config oehost-$(C_COMPILER) --cflags)
CXXFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(CXX_COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(COMPILER) --variable=includedir)

all: build

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../remoteattestation.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) $(CINCLUDES) remoteattestation_u.c
	$(CXX) -g -c $(CXXFLAGS) $(INCLUDES) -I/opt/openenclave/share/pkgconfig/../../include/openenclave/3rdparty/libcxx -I/opt/openenclave/share/pkgconfig/../../include/openenclave/3rdparty/libc -I/opt/openenclave/share/pkgconfig/../../include/openenclave/3rdparty -I/opt/openenclave/share/pkgconfig/../../include host.cpp
	$(CXX) -o attestation_host host.o remoteattestation_u.o $(LDFLAGS) -L/opt/openenclave/share/pkgconfig/../../lib/openenclave/enclave -lmbedtls -lmbedcrypto

clean:
	rm -f attestation_host *.o remoteattestation_u.*  remoteattestation_args.h

