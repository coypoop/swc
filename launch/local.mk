# swc: launch/local.mk

dir := launch

$(dir)_TARGETS  := $(dir)/swc-launch
$(dir)_PACKAGES := libdrm

$(dir)/swc-launch: $(dir)/launch.o $(dir)/protocol.o
	$(link) -lm $(launch_PACKAGE_LIBS)

install-$(dir): $(dir)/swc-launch | $(DESTDIR)$(BINDIR)
	install -m 4755 launch/swc-launch $(DESTDIR)$(BINDIR)

CLEAN_FILES += $(dir)/launch.o

include common.mk

