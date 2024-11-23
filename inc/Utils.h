#pragma once

#include <string>
#include <cerrno>
#include <cstring>
#include <unordered_map>
#include <fstream> 
#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include "cJSON.h"

std::string read_entire_file(const std::string& filePath);
std::string hashmapToJSON(std::unordered_map<std::string, std::string>& buttons);
void appendToFile(const std::string& label, const std::string& action, const std::string& filename);
void serializeMap(const std::unordered_map<std::string, std::string>& map, const std::string& filename);
void deserializeMap(std::unordered_map<std::string, std::string>& map, const std::string& filename);
void executeCommand(const std::string& command);


