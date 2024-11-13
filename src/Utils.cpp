#include <iostream>

#include <Utils.h>
#include "cJSON.h"


/* ----------------------- UTILS---------------------------------*/
std::string read_entire_file(const std::string& filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file: " << filePath << std::endl;
        return "";
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    return content;
}

std::string hashmapToJSON(std::unordered_map<std::string, std::string>& buttons) 
{
    cJSON *root = cJSON_CreateObject();
    cJSON *buttonArray = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "buttons", buttonArray);

    for (const auto &pair : buttons) {
        cJSON *button = cJSON_CreateObject();
        cJSON_AddStringToObject(button, "label", pair.first.c_str());
        cJSON_AddStringToObject(button, "action", pair.second.c_str());
        cJSON_AddItemToArray(buttonArray, button);
    }

    char *jsonString = cJSON_Print(root);
    std::string result(jsonString);
    cJSON_Delete(root);
    free(jsonString);

    return result;
}

void appendToFile(const std::string& label, const std::string& action, const std::string& filename) 
{
    std::ofstream outFile;
    outFile.open(filename, std::ios::app); 
    if (!outFile) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }
    outFile << label << ":" << action << std::endl;
    outFile.close();
}

void serializeMap(const std::unordered_map<std::string, std::string>& map, const std::string& filename) 
{
    std::ofstream file(filename);
    
    if (!file.is_open()) {
        std::cerr << "Could not open file for writing\n";
        return;
    }

    for (const auto& pair : map) {
        file << pair.first << ":" << pair.second << "\n";  // Using ':' as a delimiter
    }

    file.close();  
}

void deserializeMap(std::unordered_map<std::string, std::string>& map, const std::string& filename) 
{
    std::ifstream file(filename);
    
    if (!file.is_open()) {
        std::cerr << "Could not open file for reading\n";
        return;
    }

    std::string line;

    while (std::getline(file, line)) 
    {
        size_t delimiterPos = line.find(':');
        if (delimiterPos != std::string::npos) {
            std::string key = line.substr(0, delimiterPos);
            std::string value = line.substr(delimiterPos + 1);
            
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            map[key] = value;
        }
    }

    file.close();
}