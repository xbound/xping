CC := gcc
CFLAG := -Wall -lc -lpthread -DDOC_BIN
RFLAG := -Ofast -DRELEASE
DFLAG := -O0 -g
kernel := $(shell uname -r)
ker_version_lt_5.11 := $(shell bash "$(PWD)/klt5_11.sh" $(kernel))
ifeq ($(ker_version_lt_5.11),eg)
	CFLAG += -DUSE_EPOLL_PWAIT2
endif 
.PHONY:all
all:xping xping_g synkill synkill_g
	rm -f "$(PWD)/license_bin"
	@echo Done

#.PHONY:release
xping: xping.c klt5_11.sh license_bin
	$(CC) $(RFLAG) $(CFLAG) "$(PWD)/xping.c" -o "$(PWD)/xping"
	strip --strip-all "$(PWD)/xping"
#.PHONY:debug
xping_g: xping.c klt5_11.sh license_bin
	$(CC) $(DFLAG) $(CFLAG) "$(PWD)/xping.c" -o "$(PWD)/xping_g"
#	ln -f -s "$(PWD)/xping_g" "$(PWD)/synkill_g"
.PHONY:license_bin
license_bin: LICENSE
	xxd -i <"$(shell head -n 1 $(PWD)/LICENSE)" >"$(PWD)/license_bin"
synkill: xping
	ln -f -s "./xping" "$(PWD)/synkill"
synkill_g: xping_g
	ln -f -s "./xping_g" "$(PWD)/synkill_g"
.PHONY:clean
clean:
	rm -f "$(PWD)/xping" "$(PWD)/xping_g" 
	rm -f "$(PWD)/synkill" "$(PWD)/synkill_g"
	rm -f "$(PWD)/license_bin" 




