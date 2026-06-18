COMPILER=gcc
AR=ar

STD_FLAGS=-std=c11
WARN_FLAGS=-Wall -Wextra -pedantic
INCLUDE_FLAGS=-Isrc/shared

# Feature selection: the deliverable targets Linux, where POSIX.1-2008 exposes
# sockets, pselect, sigaction and threaded name resolution. macOS gates the same
# API behind its own feature macro, so select it there to keep local builds working.
# macOS additionally needs <signal.h> force-included: it only declares the
# signal API there, whereas Linux reaches it through <sys/signal.h> directly.
ifeq ($(shell uname -s),Darwin)
FEATURE_FLAGS=-D_DARWIN_C_SOURCE -include signal.h
else
FEATURE_FLAGS=-D_POSIX_C_SOURCE=200809L
endif

COMPILER_FLAGS=$(STD_FLAGS) $(FEATURE_FLAGS) $(WARN_FLAGS) $(INCLUDE_FLAGS) -g
LD_FLAGS=-pthread

# Unit tests are written against the Check framework (libcheck.github.io/check).
# Discover it through pkg-config when available so out-of-path installs (e.g.
# Homebrew on macOS) work; fall back to a plain -lcheck otherwise.
# Treat Check's headers as system headers so -pedantic stays silent about them.
TEST_CFLAGS=$(shell pkg-config --cflags check 2>/dev/null | sed 's/-I/-isystem /g')
TEST_LD_FLAGS=$(shell pkg-config --libs check 2>/dev/null || echo -lcheck) -pthread
