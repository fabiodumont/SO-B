obj-m += moduloCriptografia.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod moduloCriptografia.ko key="1234567890abcdef" iv="1234567890abcdef"	
	gcc prog.c -o prog
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

new:
	sudo rmmod moduloCriptografia.ko	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	sudo insmod moduloCriptografia.ko key="1234567890abcdef" iv="1234567890abcdef"

prog:
	gcc prog.c -o prog


