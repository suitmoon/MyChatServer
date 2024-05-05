set -x
rm -rf `pwd`/build/*
rm -rf `pwd`/bin/*
cd `pwd`/build &&cmake .. && 
make
