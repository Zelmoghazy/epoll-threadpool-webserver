#pragma once

#include <iostream>
#include <fstream> 
#include <cerrno>
#include <cstring>
#include <string>
#include <unordered_map>

#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#include "cJSON.h"

std::string read_entire_file(const std::string& filePath);
std::string map_to_json(std::unordered_map<std::string, std::string>& buttons);
void append_to_file(const std::string& label, const std::string& action, const std::string& filename);
void map_serialize(const std::unordered_map<std::string, std::string>& map, const std::string& filename);
void map_deserialize(std::unordered_map<std::string, std::string>& map, const std::string& filename);
void execute_command(const std::string& command);
