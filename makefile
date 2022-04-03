target=main
cppfile=mydb.cpp main.cpp
headfile=mydb.h Packet.h
mysqlopt=`mysql_config --cflags --libs`
cryptopt=-lcryptopp
CC=g++

$(target):$(cppfile) $(headfile) makefile
	$(CC) $(cppfile) $(cryptopt) $(mysqlopt) -o $(target)