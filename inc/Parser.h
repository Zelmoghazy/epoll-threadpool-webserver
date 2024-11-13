#include <iostream>
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <unordered_map>
#include <cstring> 
#include <fstream> 

#include "../inc/cJSON.h"

class JsonBuilder {
private:
    cJSON* root;

    cJSON* categories;
    cJSON* subcategories;

    cJSON* current_category;
    cJSON* current_subcategory;
    
    bool has_subcategory;
    
    std::string current_category_name;
    std::string current_subcategory_name;
    
    static const std::string default_sub;

public:
    JsonBuilder();
    ~JsonBuilder();
    void add_category(const std::string& name);
    void add_subcategory(const std::string& name);
    void add_item(const std::string& command);
    std::string get_json_string() const;
    void save_to_file(const std::string& filename) const;
};

class Parser {
private:
    JsonBuilder builder;
    std::string response;

    std::string trim(const std::string& str);
    std::string parse_cat(const std::string& line);
    std::string extract_command_name(const std::string& line, std::unordered_map<std::string, std::string>& buttons);
public:
    Parser();
    void parse_file(const std::string& filename, std::unordered_map<std::string, std::string>& buttons);
    void save_json(const std::string& filename);
    std::string& get_json();
};
