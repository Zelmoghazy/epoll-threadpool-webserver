#include "Database.h"

Database::Database(const char* s)
{
    int ret = sqlite3_open(s, &DB);
    if(ret != SQLITE_OK){
        std::cerr << "Error occurred while opening sqlite connection:" 
                  << s << '-' << sqlite3_errmsg(DB) 
                  << std::endl; 
		sqlite3_close(DB);
    }
}

Database::~Database()
{
    if(DB){
        sqlite3_close(DB);
    }
}

int Database::createTable(void)
{
	char* messageError;

	std::string sql = "CREATE TABLE IF NOT EXISTS GRADES("
		"ID INTEGER PRIMARY KEY AUTOINCREMENT, "
		"NAME      TEXT NOT NULL, "
		"LNAME     TEXT NOT NULL, "
		"AGE       INT  NOT NULL, "
		"ADDRESS   CHAR(50), "
		"GRADE     CHAR(1) );";

    /* 
        An open database, SQL to be evaluated, Callback function, 
        1st argument to callback, Error msg written here 
    */
    int ret = sqlite3_exec(DB, sql.c_str(), NULL, 0, &messageError);
    
    if (ret != SQLITE_OK) 
    {
        std::cerr << "Error in createTable function." << std::endl;
        sqlite3_free(messageError);
    }
    else
    {
        std::cout << "Table created Successfully" << std::endl;
    }

	return 0; 
}


int Database::insertData(void)
{
	char* messageError;
		
	std::string sql
    (
        "INSERT INTO GRADES (NAME, LNAME, AGE, ADDRESS, GRADE) VALUES('Alice', 'Chapa', 35, 'Tampa', 'A');"
		"INSERT INTO GRADES (NAME, LNAME, AGE, ADDRESS, GRADE) VALUES('Bob', 'Lee', 20, 'Dallas', 'B');"
		"INSERT INTO GRADES (NAME, LNAME, AGE, ADDRESS, GRADE) VALUES('Fred', 'Cooper', 24, 'New York', 'C');"
    );

	/* 
        An open database, SQL to be evaluated, Callback function,
        1st argument to callback, Error msg written here 
    */
	int ret = sqlite3_exec(DB, sql.c_str(), NULL, 0, &messageError);
	if (ret != SQLITE_OK) {
		std::cerr << "Error in insertData function." << std::endl;
		sqlite3_free(messageError);
	}
	else
    {
		std::cout << "Records inserted Successfully!" << std::endl;
    }
	return 0;
}

int Database::updateData(void)
{
	char* messageError;

	std::string sql
    (
        "UPDATE GRADES SET GRADE = 'A' WHERE LNAME = 'Cooper'"
    );

	/* 
        An open database, SQL to be evaluated, Callback function, 
        1st argument to callback, Error msg written here 
    */
	int ret = sqlite3_exec(DB, sql.c_str(), NULL, 0, &messageError);
	if (ret != SQLITE_OK) {
		std::cerr << "Error in updateData function." << std::endl;
		sqlite3_free(messageError);
	}
	else
    {
		std::cout << "Records updated Successfully!" << std::endl;
    }

	return 0;
}

int Database::deleteData(void)
{
	char* messageError;

	std::string sql = "DELETE FROM GRADES;";
    
	/* 
        An open database, SQL to be evaluated, Callback function, 
        1st argument to callback, Error msg written here 
    */
	int ret = sqlite3_exec(DB, sql.c_str(), callback, NULL, &messageError);
	if (ret != SQLITE_OK) {
		std::cerr << "Error in deleteData function." << std::endl;
		sqlite3_free(messageError);
	}
	else
    {
		std::cout << "Records deleted Successfully!" << std::endl;
    }

	return 0;
}

int Database::selectData(void)
{
	char* messageError;

	std::string sql = "SELECT * FROM GRADES;";

	/* An open database, SQL to be evaluated, Callback function, 1st argument to callback, Error msg written here*/
	int ret = sqlite3_exec(DB, sql.c_str(), callback, NULL, &messageError);

	if (ret != SQLITE_OK) {
		std::cerr << "Error in selectData function." << std::endl;
		sqlite3_free(messageError);
	}
	else
    {
		std::cout << "Records selected Successfully!" << std::endl;
    }

	return 0;
}

/*
    retrieve contents of database used by selectData()
    - argc: holds the number of results, 
    - argv: holds each value in array, 
    - azColName: holds each column returned in array, 
*/
int Database::callback(void* NotUsed, int argc, char** argv, char** azColName)
{
	for (int i = 0; i < argc; i++) {
		// column name and value
		std::cout << azColName[i] << ": " << argv[i] << std::endl;
	}

	std::cout << std::endl;

	return 0;
}
