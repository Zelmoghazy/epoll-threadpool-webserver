#pragma once

#include <stdexcept>

class ServerException : public std::runtime_error {
public:
    explicit ServerException(const std::string& message); 
};