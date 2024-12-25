#include "Application.h"

using namespace AppLayout;

const std::string JsonBuilder::default_sub = "General";

JsonBuilder::JsonBuilder() : has_subcategory(false) 
{
    root       = cJSON_CreateObject();
    categories = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "categories", categories);
}

JsonBuilder::~JsonBuilder() 
{
    if (root) {
        // Delete a cJSON entity and all subentities.
        cJSON_Delete(root);
    }
}

void JsonBuilder::add_category(const std::string& name) 
{
    current_category_name = name;
    current_category      = cJSON_CreateObject();

    subcategories         = cJSON_CreateObject();

    cJSON_AddItemToObject(current_category, "subcategories", subcategories);
    cJSON_AddItemToObject(categories, current_category_name.c_str(), current_category);

    has_subcategory = false;
    
    // Reset current subcategory
    current_subcategory = nullptr;
}

void JsonBuilder::add_subcategory(const std::string& name) 
{
    has_subcategory = true;

    current_subcategory_name = name;
    current_subcategory      = cJSON_CreateObject();
    cJSON_AddItemToObject(subcategories, current_subcategory_name.c_str(), current_subcategory);
    
    // Create empty items array
    cJSON* items = cJSON_CreateArray();
    cJSON_AddItemToObject(current_subcategory, "items", items);
}

void JsonBuilder::add_item(const std::string& command) 
{

    // If no subcategories are added create a default one
    if (!current_subcategory && !has_subcategory) {
        add_subcategory(default_sub);
    }

    if (current_subcategory) 
    {
        cJSON* items = cJSON_GetObjectItem(current_subcategory, "items");
        if (items) {
            cJSON_AddItemToArray(items, cJSON_CreateString(command.c_str()));
        }
    }
}

std::string JsonBuilder::get_json_string() const 
{
    char* json_str = cJSON_Print(root);
    std::string result(json_str);
    free(json_str);
    return result;
}

void JsonBuilder::save_to_file(const std::string& filename) const 
{
    std::ofstream out(filename);
    if (out.is_open()) {
        out << get_json_string();
    }
}

Parser::Parser()
{
    this->response.reserve(2024);
}

/* Return line without beginning or end whitespace */
std::string Parser::trim(const std::string& str) 
{
    const auto start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos){
        return "";
    }
    const auto end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}


std::string Parser::parse_cat(const std::string& line) 
{
    size_t start = line.find_first_not_of('#');
    if (start == std::string::npos) {
        return "";
    }
    return trim(line.substr(start));
}

std::string Parser::extract_command_name(const std::string& line, std::unordered_map<std::string, std::string>& buttons) 
{
    size_t start = line.find_first_not_of("- ");
    if (start == std::string::npos) {
        return "";
    }
    size_t colon_pos = line.find(':', start);
    if (colon_pos != std::string::npos) {
        std::string command = trim(line.substr(start, colon_pos - start));
        std::string value = trim(line.substr(colon_pos + 1));
        buttons[command] = value;
        return command;
    }
    // no colon found just return whatever is there
    return trim(line.substr(start));
}

/*
    The simplest way I could think of, doesnt handle any errors
*/
void Parser::parse_file(const std::string& filename, std::unordered_map<std::string, std::string>& buttons) 
{
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filename);
    }

    std::string line;
    while (std::getline(file, line)) 
    {
        line = trim(line);

        if (line.empty()){
            continue;
        } 

        // category check
        if (line[0] == '#') {
            if (line[1] == '#') {  // Subcategory
                builder.add_subcategory(parse_cat(line));
            } else {  // Category
                builder.add_category(parse_cat(line));
            }
        } else if (line[0] == '-') {  // Item
            builder.add_item(extract_command_name(line, buttons));
        }
    }
    response.clear();
    response += builder.get_json_string();    
}

void Parser::save_json(const std::string& filename) 
{
    builder.save_to_file(filename);
}

std::string& Parser::get_json() 
{
    return response;
}


using namespace modules;



notes::notes()
{
    schema = cJSON_CreateObject();
    cJSON_AddNumberToObject(schema, "category", static_cast<double>(FIELD_TYPES::TEXT));
    cJSON_AddNumberToObject(schema, "timestamp", static_cast<double>(FIELD_TYPES::DATETIME));
    cJSON_AddNumberToObject(schema, "content", static_cast<double>(FIELD_TYPES::TEXT));

    // check if it exists what happens
    db = new Database("notes.db");
    db->create_table(TABLE_NAME, schema);
}

notes::~notes()
{
    if (schema) {
        cJSON_Delete(schema);
    }
}