LD_LIBRARY_PATH=/usr/local/lib
export LD_LIBRARY_PATH
gcc -g -o quicksand.out quicksand.c  -L/usr/local/lib -lyara -lzip -lz
