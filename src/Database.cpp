#include "Database.h"
#include <cstring>
#include <stdexcept>

const char* FIELD_TYPES_str[] = {
    LIST_FIELD_TYPES(STRING_GEN)
};


std::string Database::val_to_sql(cJSON* value) 
{
    switch (value->type) 
    {
        case cJSON_String:
            return "'" + std::string(value->valuestring) + "'";
        case cJSON_NULL:
            return "NULL";
        case cJSON_Number:
            return std::to_string(value->valuedouble);
        case cJSON_True:
            return "1";
        case cJSON_False:
            return "0";
        default:
            return "NULL";
    }
}

Database::Database(const std::string& path)
{
    if(sqlite3_open(path.c_str(), &db) != SQLITE_OK){
        throw std::runtime_error(sqlite3_errmsg(db));
    }
    query.reserve(8192);
}

Database::~Database()
{
    if(db){
        sqlite3_close(db);
    }
}

void Database::execute_query() 
{
    char* errMsg = nullptr;
    if (sqlite3_exec(db, query.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::string error = errMsg;
        sqlite3_free(errMsg);
        throw std::runtime_error("Query failed: " + error);
    }
    query.clear();
}

void Database::create_table(const std::string& tableName, cJSON* schema)
{
    query += "CREATE TABLE IF NOT EXISTS " + tableName + " (";
    query += "id INTEGER PRIMARY KEY AUTOINCREMENT, ";
        
    cJSON* field;
    cJSON_ArrayForEach(field, schema) {
        query += field->string;
        query += " ";
        query += get_sql_type(static_cast<FIELD_TYPES>(static_cast<int>(cJSON_GetNumberValue(field))));
        query += ", ";
    }
    query.pop_back();
    query.pop_back(); // Remove last comma
    query += ");";

    execute_query();
}


void Database::insert(const std::string& tableName, cJSON* data) 
{
    std::string columns = "", values = "";
    cJSON* value;
    cJSON_ArrayForEach(value, data) {
        if (strcmp(value->string, "id") != 0) {
            columns += value->string;
            columns += ", ";
            values += val_to_sql(value);
            values += ", ";
        }
    }
    columns.pop_back(); columns.pop_back();
    values.pop_back(); values.pop_back();

    query += "INSERT INTO " + tableName + " (" + columns + ") VALUES (" + values + ");";
    execute_query();
}

cJSON* Database::select(const std::string& tableName, const std::string& condition) 
{
    query += "SELECT * FROM " + tableName;

    if (!condition.empty()){
        query += " WHERE " + condition;
    }

    cJSON* result = cJSON_CreateArray();

    auto callback = [](void* data, int argc, char** argv, char** colNames) -> int 
    {
        cJSON* result = static_cast<cJSON*>(data);
        cJSON* row = cJSON_CreateObject();
        
        for (int i = 0; i < argc; i++) 
        {
            if (argv[i])
            {
                cJSON_AddStringToObject(row, colNames[i], argv[i]);
            }
            else 
            {
                cJSON_AddNullToObject(row, colNames[i]);
            }
        }
        cJSON_AddItemToArray(result, row);
        return 0;
    };
    

    char* errMsg = nullptr;
    if (sqlite3_exec(db, query.c_str(), callback, result, &errMsg) != SQLITE_OK) {
        std::string error = errMsg;
        sqlite3_free(errMsg);
        cJSON_Delete(result);
        throw std::runtime_error("Select failed: " + error);
    }

    query.clear();

    return result;
}

void Database::update(const std::string& tableName, cJSON* data, const std::string& condition) 
{
    std::string updates;
    cJSON* value;
    cJSON_ArrayForEach(value, data) 
    {
        if (strcmp(value->string, "id") != 0) {
            updates += value->string;
            updates += " = ";
            updates += val_to_sql(value);
            updates += ", ";
        }
    }
    updates.pop_back(); 
    updates.pop_back();

    query += "UPDATE " + tableName + " SET " + updates;
    if (!condition.empty())
    {
        query += " WHERE " + condition;
    } 

    execute_query();
}

void Database::remove(const std::string& tableName, const std::string& condition) 
{
    query += "DELETE FROM " + tableName;
    if (!condition.empty())
    {
        query += " WHERE " + condition;
    }
    execute_query();
}

const char* Database::field_type_to_str(FIELD_TYPES ft)
{
    return FIELD_TYPES_str[static_cast<int>(ft)];
}

std::string Database::get_sql_type(FIELD_TYPES type) 
{
    auto it = sqlite_map.find(type);
    if (it == sqlite_map.end()) {
        throw std::runtime_error("Unsupported field type");
    }
    return it->second;
}