Workaround for zipconfig.h not found error during compile

For Linux/Mac:
ln -vs  /usr/local/lib/libzip/include/zipconf.h /usr/local/include

On MacOs installed via brew:
> ln -vs /usr/local/opt/libzip/lib/libzip/include/zipconf.h /usr/local/include


