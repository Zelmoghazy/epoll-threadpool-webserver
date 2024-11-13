#include "ServerException.h"

ServerException::ServerException(const std::string& message) : std::runtime_error(message) {}
