#pragma once

#include "sqlite3.h"
#include <string>
#include <iostream>
#include <string>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include "cJSON.h"

#define ENUM_GEN(ENUM)     ENUM,
#define STRING_GEN(STRING) #STRING,

/*
    The idea till now is to have a common schema and deal with it 
    and generate equivalent code for both database and json sent and 
    received from the client
 */

#define LIST_FIELD_TYPES(FIELD_TYPES) \
    FIELD_TYPES(TEXT)                 \
    FIELD_TYPES(INTEGER)              \
    FIELD_TYPES(REAL)                 \
    FIELD_TYPES(BOOLEAN)              \
    FIELD_TYPES(DATE)                 \
    FIELD_TYPES(DATETIME)             \
    FIELD_TYPES(BLOB)                 \
    FIELD_TYPES(VARCHAR)              \
    FIELD_TYPES(COUNT)                \

enum class FIELD_TYPES {
    LIST_FIELD_TYPES(ENUM_GEN)
};

struct Database
{
    sqlite3 *db=nullptr;
    std::string query;
    const std::unordered_map<FIELD_TYPES, std::string> sqlite_map = 
    {
        {FIELD_TYPES::TEXT, "TEXT"},
        {FIELD_TYPES::INTEGER, "INTEGER"},
        {FIELD_TYPES::REAL, "REAL"},
        {FIELD_TYPES::BOOLEAN, "INTEGER"},
        {FIELD_TYPES::DATE, "TEXT"},
        {FIELD_TYPES::DATETIME, "TEXT"},
        {FIELD_TYPES::BLOB, "BLOB"},
        {FIELD_TYPES::VARCHAR, "TEXT"}
    };

    Database(const std::string& path);
    ~Database();
    void execute_query(void); 
    void create_table(const std::string& tableName, cJSON* schema);
    void insert(const std::string& tableName, cJSON* data);
    cJSON* select(const std::string& tableName, const std::string& condition = "");
    void update(const std::string& tableName, cJSON* data, const std::string& condition);
    void remove(const std::string& tableName, const std::string& condition = ""); 
    std::string val_to_sql(cJSON* value);
    static const char* field_type_to_str(FIELD_TYPES ft);
    std::string get_sql_type(FIELD_TYPES type);
};
