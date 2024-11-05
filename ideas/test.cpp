#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cJSON.h>

/* Return line without beginning or end whitespace */
std::string trim(const std::string& str) 
{
    // first pos not a white space
    const auto start = str.find_first_not_of(" \t\r\n");
    // entire line is white space
    if (start == std::string::npos){
        return "";
    }
    // last pos not a whitespace 
    const auto end = str.find_last_not_of(" \t\r\n");
    
    return str.substr(start, end - start + 1);
}

// Function to clean category/subcategory names (remove # and spaces)
std::string parse_cat(const std::string& line) 
{
    size_t start = line.find_first_not_of('#');
    if (start == std::string::npos) {
        return "";
    }
    return trim(line.substr(start));
}

std::string extract_command_name(const std::string& line) 
{
    size_t start = line.find_first_not_of("- ");
    if (start == std::string::npos) {
        return "";
    }
    size_t colon_pos = line.find(':', start);
    if (colon_pos != std::string::npos) {
        std::string command = trim(line.substr(start, colon_pos - start));
        std::string value = trim(line.substr(colon_pos + 1));
        return command;
    }

    // no colon found just return whatever is there
    return trim(line.substr(start));
}

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
    
    static const std::string DEFAULT_SUBCATEGORY;

public:
    JsonBuilder() : has_subcategory(false) {
        root       = cJSON_CreateObject();
        categories = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "categories", categories);
    }

    ~JsonBuilder() {
        if (root) {
            cJSON_Delete(root);
        }
    }

    void add_category(const std::string& name) 
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

    void add_subcategory(const std::string& name) 
    {
        has_subcategory = true;

        current_subcategory_name = name;
        current_subcategory = cJSON_CreateObject();
        cJSON_AddItemToObject(subcategories, current_subcategory_name.c_str(), current_subcategory);
        
        // Create empty items array
        cJSON* items = cJSON_CreateArray();
        cJSON_AddItemToObject(current_subcategory, "items", items);
    }

    void add_item(const std::string& command) {
        // If no subcategories are added create a default one
        if (!current_subcategory && !has_explicit_subcategory) {
            add_subcategory(DEFAULT_SUBCATEGORY);
        }

        if (current_subcategory) {
            cJSON* items = cJSON_GetObjectItem(current_subcategory, "items");
            if (items) {
                cJSON_AddItemToArray(items, cJSON_CreateString(command.c_str()));
            }
        }
    }

    std::string get_json_string() const 
    {
        char* json_str = cJSON_Print(root);
        std::string result(json_str);
        free(json_str);
        return result;
    }

    void save_to_file(const std::string& filename) const 
    {
        std::ofstream out(filename);
        if (out.is_open()) {
            out << get_json_string();
        }
    }
};

const std::string JsonBuilder::DEFAULT_SUBCATEGORY = "General";

class MarkdownParser {
private:
    JsonBuilder builder;

public:
    void parse_file(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("Could not open file: " + filename);
        }

        std::string line;
        while (std::getline(file, line)) {
            line = trim(line);
            if (line.empty()) continue;

            if (line[0] == '#') {
                if (line[1] == '#') {  // Subcategory
                    builder.add_subcategory(parse_cat(line));
                } else {  // Category
                    builder.add_category(parse_cat(line));
                }
            } else if (line[0] == '-') {  // Item
                builder.add_item(extract_command_name(line));
            }
        }
    }

    void save_json(const std::string& filename) {
        builder.save_to_file(filename);
    }

    std::string get_json() const {
        return builder.get_json_string();
    }
};

int main() {
    try {
        MarkdownParser parser;
        
        // Parse input file
        parser.parse_file("test.txt");
        
        // Print to console
        std::cout << parser.get_json() << std::endl;
        
        // Save to file
        parser.save_json("output.json");
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}