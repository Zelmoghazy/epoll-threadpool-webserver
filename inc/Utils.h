#pragma once

#include <string>
#include <unordered_map>
#include <fstream> 

std::string read_entire_file(const std::string& filePath);
std::string hashmapToJSON(std::unordered_map<std::string, std::string>& buttons);
void appendToFile(const std::string& label, const std::string& action, const std::string& filename);
void serializeMap(const std::unordered_map<std::string, std::string>& map, const std::string& filename);
void deserializeMap(std::unordered_map<std::string, std::string>& map, const std::string& filename);

