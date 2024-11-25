#include <Utils.h>
#include <fcntl.h>

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

void executeCommand(const std::string& command)
{
    // will handle piping output later
    pid_t pid = fork();
    
    if (pid < 0) {
        std::cerr << "Fork failed: " << std::strerror(errno) << std::endl;
        return;
    }
    else if (pid == 0) 
    {  
        // Open /dev/null for redirection
        int devNull = open("/dev/null", O_WRONLY);
        if (devNull == -1) {
            std::cerr << "Failed to open /dev/null: " << std::strerror(errno) << std::endl;
            exit(1);
        }

        // Redirect stdout and stderr to /dev/null
        if (dup2(devNull, STDOUT_FILENO) == -1) {
            std::cerr << "Failed to redirect stdout: " << std::strerror(errno) << std::endl;
            exit(1);
        }
        if (dup2(devNull, STDERR_FILENO) == -1) {
            std::cerr << "Failed to redirect stderr: " << std::strerror(errno) << std::endl;
            exit(1);
        }

        close(devNull);

        execl("/bin/sh", "sh", "-c", command.c_str(), (char*)nullptr);
        
        // If execl fails
        std::cerr << "Failed to execute: " << std::strerror(errno) << std::endl;
        exit(1);
    }
    else
    {
        // Parent process
        int status;
        pid_t result = waitpid(pid, &status, 0);

        if (result == -1) {
            std::cerr << "waitpid failed" << std::endl;
            return;
        }

        if (WIFEXITED(status)) {
            std::cout << "Child process exited with status: " << WEXITSTATUS(status) << std::endl;
        } else if (WIFSIGNALED(status)) {
            std::cout << "Child process terminated by signal: " << WTERMSIG(status) << std::endl;
        }
    }
}