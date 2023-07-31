
remount:
	@echo "cuttlefish remount, begin"
	./bin/adb root
	sleep 1
	./bin/adb remount
	./bin/adb reboot
	sleep 20
	./bin/adb root
	@echo "cuttlefish reboot, done"

mount-sec:
	sleep 30
	./bin/adb shell "mount -t securityfs securityfs /sys/kernel/security"
	@echo "cuttlefish securityfs mount, done"

mount-debug:
	./bin/adb shell "mount -t debugfs debugfs /sys/kernel/debug"
	@echo "cuttlefish debugfs mount, done"

mount-sys:
	./bin/adb shell "mount -o rw,remount /system"
	@echo "cuttlefish /system mount rw, done"

mount: mount-sec mount-debug mount-sys

remount-all: remount mount


prepare:
	./bin/adb push /home/michaelxi/Downloads/camflowd /data/local/tmp
	@echo "camflowd executable copied to /data/local/tmp, done"
	./bin/adb push /home/michaelxi/Downloads/camflowexample /data/local/tmp
	@echo "camflowexample executable copied to /data/local/tmp, done"
	./bin/adb push /home/michaelxi/Downloads/camconfd /data/local/tmp
	@echo "camconfd executable copied to /data/local/tmp, done"
	./bin/adb shell "cd /data/local/tmp && chmod 777 camflowd && chmod 777 camflowexample && chmod 777 camconfd"
	@echo "camflowd, camflowexample, camconfd chomod, done"
	./bin/adb push /home/michaelxi/Downloads/camflowd.ini /data/local/tmp
	@echo "camflowd.ini configuration copy, done"
	./bin/adb push /home/michaelxi/Downloads/camflow.ini /data/local/tmp
	@echo "camflow.ini configuration copy, done"
	./bin/adb push /home/michaelxi/Downloads/input.txt /data/local/tmp
	@echo "input.txt copy, done"
	./bin/adb push /home/michaelxi/Downloads/libprovenance.so /system/lib64
	@echo "libprovenance.so copy, done"
	./bin/adb push /home/michaelxi/Downloads/camflow-cli /system/bin
	@echo "camflow-cli copy, done"
	./bin/adb shell "cd /system/bin && mv camflow-cli camflow"
	./bin/adb shell "chmod 777 /system/bin/camflow"
	@echo "camflow-cli chmod, done"


clean:
	./bin/adb shell "cd /data/local/tmp && rm *"
	@echo "clean, done"

run-camflowd:
	./bin/adb shell "/data/local/tmp/camflowd" &
	@echo "camflowd executed, done"

run-camconfd:
	./bin/adb shell "/data/local/tmp/camconfd" &
	@echo "camconfd executed, done"

run-example:
	./bin/adb shell "/data/local/tmp/camflowexample"
	@echo "camflow example executed, done"

run: run-camconfd run-camflowd run-example


stop:
	@echo "stop previous cuttlefish device"
	HOME=$$PWD ./bin/stop_cvd
	@echo "cuttlefish device stop, done"

shell:
	./bin/adb shell

root:
	./bin/adb root

pull:
	./bin/adb pull /data/local/tmp/audit.log /home/michaelxi/Documents
	@echo "pull audit.log from cuttlefish to Documents, done"