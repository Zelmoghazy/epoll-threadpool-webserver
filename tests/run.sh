g++ -std=c++17 -I../external/inc/ -c ../external/src/catch_amalgamated.cpp -o catch.o
ar rcs libcatch.a ./catch.o
g++ -std=c++17 -Wall tests.cpp -L. -lcatch -o test_program