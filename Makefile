FILE := "main"
obj-m += main.o

.SILENT:
all:
	echo "Compiling $(FILE)..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	echo "OK"
clean:	
	echo "Cleaning modules..."
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	echo "Cleaned up"
fclean: clean
	echo "Removing object files..."
	rm -rf .$(FILE).ko.cmd .$(FILE).mod.o.cmd .$(FILE).o.cmd .cache.mk .tmp_versions $(FILE).ko $(FILE).o $(FILE).mod.c $(FILE).mod.o modules.order Module.symvers 2>&-
	echo "Done"
test:
	echo "Testing..."
	insmod $(FILE).ko 2>&-
	dmesg | tail -1 2>&-
	rmmod $(FILE).ko 2>&-
	dmesg | tail -1 2>&-
