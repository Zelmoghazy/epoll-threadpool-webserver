#include "sqlite3.h"
#include <string>
#include <iostream>

struct Database
{
    sqlite3 *DB=nullptr;

    Database(const char* s);
    ~Database();
    int createTable(void);
    int insertData(void);
    int updateData(void);
    int deleteData(void);
    int selectData(void);
    static int callback(void* NotUsed, int argc, char** argv, char** azColName);
};